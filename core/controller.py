"""
WebOSINT Pro - Scan Controller

Orchestration only. Safety policy lives in core.safety, networking in
core.netclient, finding normalization in core.findings and rendering in
core.render / reports.

Behaviour:
  * refuses to run unless the safety gate has already passed
  * passive modules by default; active modules only with --active
  * bounded concurrency, per-module timeouts, cooperative cancellation
  * deduplicated, deterministically ordered findings
  * redacted, low-noise console output
"""

from __future__ import annotations

import random
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timezone
from typing import Any

from core.config import ACTIVE_MODULES
from core.findings import FindingCollector, Severity
from core.infrastructure import build_infrastructure
from core.netclient import ScanCancelled
from core.plugin_registry import PluginRegistry
from core.redaction import DEFAULT_REDACTOR
from core.risk_rollup import count_severities, derive_legacy_findings, merge_findings
from core.safety import AuthorizationError, SafetyController
from reporting.base import BaseReport
from reporting.export import write_reports
from utils.output import ColorOutput as C
from utils.rate_limiter import RateLimiter

RISK_ORDER = ["critical", "high", "medium", "low", "info"]
MODULE_TIMEOUT_SECONDS = 300

# Sequential-first modules feed data the rest depend on.
SEQUENTIAL_FIRST = ("dns", "ip", "whois", "http", "ssl")


class ScanController:
    def __init__(
        self,
        config: Any,
        logger: Any,
        safety: SafetyController | None = None,
        cancel_event: threading.Event | None = None,
    ) -> None:
        self.cfg = config
        self.logger = logger
        self.verbose: int = getattr(config, "verbose", 0)
        self.quiet: bool = getattr(config, "quiet", False)
        self.safety = safety or getattr(config, "safety", None) or SafetyController()
        self.redactor = getattr(config, "redactor", DEFAULT_REDACTOR)
        self.cancel_event = cancel_event or threading.Event()

        # A scan may never start without a passing authorization gate.
        self.safety.policy.require_authorized()

        self.rate_limiter = RateLimiter(config.rate_limit)
        self.collector = FindingCollector(
            self.redactor, untrusted=not self.safety.policy.results_trusted
        )

        self._lock = threading.Lock()
        self._completed = 0
        self._total_mods = 0
        self._running: set[str] = set()
        self.start_time = time.time()

        # Optional progress sink used by the web UI. Never required.
        self.progress_callback = getattr(config, "progress_callback", None)
        # Real on-disk report paths. results["reports"] is redacted for display
        # and must never be used to open files.
        self.report_paths: list[str] = []

        self.results: dict[str, Any] = {
            "meta": {
                "target": config.target,
                "mode": "active" if self.safety.policy.active else "passive",
                "detail_level": getattr(config, "detail", "standard"),
                "tls_verified": self.safety.policy.verify_tls,
                "results_trusted": self.safety.policy.results_trusted,
                "session_id": getattr(config, "session_id", ""),
                "start_time": datetime.now(tz=timezone.utc).isoformat(),
                "modules_run": [],
                "modules_skipped": sorted(getattr(config, "skipped_active_modules", [])),
            },
            "findings": {},
            "errors": {},
            "warnings": [],
            "summary": {},
        }

        self._registry = PluginRegistry()
        self._registry.load_all()

    # ── Entry point ─────────────────────────────────────────────────────────

    def run(self) -> dict[str, Any]:
        modules = self._select_modules()
        self._total_mods = len(modules)
        self._print_header(modules)

        sequential = [m for m in SEQUENTIAL_FIRST if m in modules]
        parallel = [m for m in modules if m not in sequential]

        for name in sequential:
            if self.cancel_event.is_set():
                break
            self._run_module(name)
            self._pace()

        if parallel and not self.cancel_event.is_set():
            workers = max(1, min(int(self.cfg.threads), len(parallel)))
            pool = ThreadPoolExecutor(max_workers=workers)
            try:
                futures = {pool.submit(self._run_module, m): m for m in parallel}
                pending = set(futures)
                deadline = time.time() + MODULE_TIMEOUT_SECONDS
                while pending:
                    _done, pending = wait(pending, timeout=1.0, return_when=FIRST_COMPLETED)
                    if self.cancel_event.is_set():
                        for future in pending:
                            future.cancel()
                        break
                    if pending and time.time() >= deadline:
                        self._abandon_stalled(futures, pending)
                        break
            finally:
                pool.shutdown(wait=False)

        elapsed = time.time() - self.start_time
        self.results["meta"]["end_time"] = datetime.now(tz=timezone.utc).isoformat()
        self.results["meta"]["elapsed_seconds"] = round(elapsed, 2)
        self.results["meta"]["cancelled"] = self.cancel_event.is_set()

        self._build_summary()
        reports = self._generate_reports()
        self._print_summary(elapsed, reports)

        self.report_paths = list(reports)
        self.results["reports"] = [self.redactor.path(p) for p in reports]
        self._emit_progress(event="finished")
        return self.results

    # ── Progress ─────────────────────────────────────────────────────────────

    def _abandon_stalled(self, futures: dict, pending: set) -> None:
        """Stop waiting on modules that blew past the per-module time budget.

        Python cannot kill a running thread, so the work is abandoned rather
        than truly stopped: the scan moves on and reports what it already has
        instead of hanging forever on one wedged module.
        """
        stalled = sorted(futures[future] for future in pending)
        for future in pending:
            future.cancel()
        for name in stalled:
            self.results["errors"][name] = f"timed out after {MODULE_TIMEOUT_SECONDS}s"
            with self._lock:
                self._running.discard(name)
                self._completed += 1
        self.results["warnings"].append(
            f"{len(stalled)} module(s) exceeded the {MODULE_TIMEOUT_SECONDS}s budget "
            f"and were abandoned: {', '.join(stalled)}"
        )
        self.logger.warning(f"module timeout after {MODULE_TIMEOUT_SECONDS}s: {', '.join(stalled)}")
        self._emit_progress(event="timeout")

    def _emit_progress(self, module: str = "", event: str = "") -> None:
        """Publish progress to an optional callback.

        A misbehaving callback must never be able to break a scan, so every
        failure here is swallowed deliberately.
        """
        callback = self.progress_callback
        if callback is None:
            return
        with self._lock:
            completed = self._completed
            running = sorted(self._running)
        total = self._total_mods or 0
        percent = round((completed / total) * 100, 1) if total else 0.0
        try:
            callback(
                {
                    "event": event,
                    "module": module,
                    "completed": completed,
                    "total": total,
                    "percent": percent,
                    "running": running,
                    "elapsed": round(time.time() - self.start_time, 1),
                }
            )
        except Exception:
            pass

    # ── Module selection ─────────────────────────────────────────────────────

    def _select_modules(self) -> list[str]:
        requested = list(dict.fromkeys(self.cfg.modules))  # stable de-dup
        selected: list[str] = []
        for name in requested:
            if not self._registry.is_registered(name):
                self.logger.debug(f"unknown module skipped: {name}")
                continue
            if name in ACTIVE_MODULES and not self.safety.policy.active:
                continue
            selected.append(name)

        skipped = self.results["meta"]["modules_skipped"]
        if skipped and not self.quiet:
            self.results["warnings"].append(
                f"{len(skipped)} active module(s) skipped in passive mode: "
                f"{', '.join(skipped)} (use --active to enable)"
            )
        if getattr(self.cfg, "randomize_order", False):
            random.shuffle(selected)
        return selected

    # ── Execution ────────────────────────────────────────────────────────────

    def _run_module(self, name: str) -> None:
        if self.cancel_event.is_set():
            return

        with self._lock:
            self._running.add(name)
        self.logger.module_start(name)
        self._emit_progress(module=name, event="module_start")
        started = time.perf_counter()
        instance = None
        try:
            klass = self._registry.get(name)
            if klass is None:
                self._record_error(name, "module not available")
                return

            instance = self._instantiate(klass, name)
            if hasattr(instance, "setup"):
                instance.setup()
            findings = instance.run() or {}

            elapsed_ms = (time.perf_counter() - started) * 1000
            safe_findings = self.redactor.data(findings)
            self.results["findings"][name] = safe_findings

            with self._lock:
                self._completed += 1
                self.results["meta"]["modules_run"].append(name)

            collector = getattr(instance, "collector", None)
            if collector is not None and collector is not self.collector:
                self.collector.extend(collector.all())

            self.logger.module_done(name, self._count(safe_findings), elapsed_ms)

        except ScanCancelled:
            self.cancel_event.set()
            self.logger.debug(f"{name} cancelled")
        except AuthorizationError as exc:
            self._record_error(name, str(exc))
        except Exception as exc:
            # Redacted message only: no traceback, no paths, no secrets.
            self._record_error(name, self.redactor.exception(exc))
        finally:
            if instance is not None and hasattr(instance, "teardown"):
                try:
                    instance.teardown()
                except Exception:
                    pass
            with self._lock:
                self._running.discard(name)
            self._emit_progress(module=name, event="module_done")

    def _instantiate(self, klass: Any, name: str) -> Any:
        """Support both the new safety-aware and the legacy 3-argument signature."""
        try:
            return klass(
                self.cfg,
                self.logger,
                self.rate_limiter,
                safety=self.safety,
                collector=self.collector,
                cancel_event=self.cancel_event,
            )
        except TypeError:
            self.logger.debug(f"{name} uses the legacy module signature")
            return klass(self.cfg, self.logger, self.rate_limiter)

    def _record_error(self, name: str, message: str) -> None:
        with self._lock:
            self._completed += 1
            self.results["errors"][name] = message
        self.logger.error(f"[{name}] {message}")

    def _pace(self) -> None:
        delay = float(getattr(self.cfg, "delay", 0) or 0)
        if delay <= 0:
            return
        jitter = random.uniform(0, getattr(self.cfg, "jitter", 0.0)) if self.cfg.stealth else 0
        self.cancel_event.wait(delay + jitter)

    # ── Output ───────────────────────────────────────────────────────────────

    def _quiet_console(self) -> bool:
        return self.quiet or getattr(self.cfg, "json_stdout", False)

    def _print_header(self, modules: list[str]) -> None:
        if self._quiet_console():
            return
        mode = "ACTIVE" if self.safety.policy.active else "passive"
        mode_color = C.RED if self.safety.policy.active else C.GREEN
        print(f"\n  {C.BOLD}Target{C.RESET}  {C.CYAN}{self.cfg.target}{C.RESET}")
        print(
            f"  {C.BOLD}Mode{C.RESET}    {mode_color}{mode}{C.RESET}  "
            f"{C.DIM}detail={getattr(self.cfg, 'detail', 'standard')} "
            f"tls={'verified' if self.safety.policy.verify_tls else 'UNVERIFIED'}{C.RESET}"
        )
        print(f"  {C.BOLD}Modules{C.RESET} {len(modules)}\n")

    def _print_summary(self, elapsed: float, reports: list[str]) -> None:
        if self._quiet_console():
            return

        summary = self.results["summary"]
        counts = summary.get("severity_counts", {})
        actionable = self.collector.actionable(Severity.LOW)

        if actionable:
            print(f"  {C.BOLD}Actionable findings{C.RESET}")
            for finding in actionable[:20]:
                color = {
                    "critical": C.RED + C.BOLD,
                    "high": C.RED,
                    "medium": C.YELLOW,
                    "low": C.CYAN,
                }.get(finding.severity.value, C.RESET)
                status = finding.status.value if finding.status else "unverified"
                print(
                    f"   {color}{finding.severity.value.upper():<8}{C.RESET} "
                    f"{finding.title}  {C.DIM}[{status}, "
                    f"confidence {finding.confidence:.0%}, via {'+'.join(finding.sources)}]{C.RESET}"
                )
            if len(actionable) > 20:
                print(f"   {C.DIM}... {len(actionable) - 20} more (see the JSON report){C.RESET}")
            print()

        for warning in self.results["warnings"]:
            print(f"  {C.YELLOW}[warn]{C.RESET} {warning}")
        for name, message in sorted(self.results["errors"].items()):
            print(f"  {C.RED}[error]{C.RESET} {name}: {message}")

        severity_line = (
            "  ".join(
                f"{level}={counts.get(level, 0)}" for level in RISK_ORDER if counts.get(level)
            )
            or "no risk findings"
        )
        status_word = "cancelled" if self.cancel_event.is_set() else "complete"
        print(
            f"\n  {C.BOLD}{C.GREEN}Scan {status_word}{C.RESET} | "
            f"{elapsed:.1f}s | modules {summary.get('modules_run', 0)}/{self._total_mods} | "
            f"findings {summary.get('total_findings', 0)} | {severity_line}"
        )
        if not self.safety.policy.results_trusted:
            print(f"  {C.YELLOW}All findings are UNTRUSTED (TLS verification disabled).{C.RESET}")
        for path in reports:
            print(f"  {C.DIM}report: {self.redactor.path(path)}{C.RESET}")
        print()

    # ── Aggregation ──────────────────────────────────────────────────────────

    @staticmethod
    def _count(data: Any) -> int:
        if isinstance(data, dict):
            return sum(
                1
                for k, v in data.items()
                if not str(k).startswith("_") and v not in (None, "", [], {})
            )
        if isinstance(data, list):
            return len(data)
        return 1 if data else 0

    def _build_summary(self) -> None:
        legacy_total = sum(self._count(d) for d in self.results["findings"].values())
        normalized = self.collector.to_dict()

        # Legacy modules report risk through set_risk(), which writes "_risk_<key>"
        # straight into module output and never touches the collector. Relying on
        # the collector alone is why the risk summary rendered all zeros while the
        # legacy count reported dozens of findings. Merge both views.
        legacy_rows = derive_legacy_findings(self.results["findings"])
        merged = merge_findings(normalized["findings"], legacy_rows)
        counts = count_severities(merged)

        self.results["normalized_findings"] = merged
        self.results["infrastructure"] = build_infrastructure(self.results["findings"])
        self.results["summary"] = {
            "target": self.cfg.target,
            "mode": self.results["meta"]["mode"],
            "session_id": getattr(self.cfg, "session_id", ""),
            "modules_run": len(self.results["meta"]["modules_run"]),
            "modules_skipped": self.results["meta"]["modules_skipped"],
            "total_findings": max(legacy_total, len(merged)),
            "unique_findings": len(merged),
            "duplicates_merged": normalized["duplicates_merged"],
            "severity_counts": counts,
            # Reports read "risk_counts"; keep both keys in sync.
            "risk_counts": counts,
            "errors": len(self.results["errors"]),
            "results_trusted": self.safety.policy.results_trusted,
        }

    # ── Reporting ────────────────────────────────────────────────────────────

    def _generate_reports(self) -> list[str]:
        """Write every requested report format.

        Format selection, directory creation and file permissions live in
        :mod:`reporting.export`; the controller only supplies the results
        and the destination.
        """
        stem = self.cfg.report_name or BaseReport.default_stem(self.cfg.target)
        return write_reports(
            self.results,
            self.cfg.output_dir,
            formats=getattr(self.cfg, "report_format", "json"),
            stem=stem,
            logger=self.logger,
        )
