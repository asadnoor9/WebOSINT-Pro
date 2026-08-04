"""
Staged scan pipeline.

The pipeline is the scheduler. It runs the cheap, high-signal stages first,
builds a technology profile from what they observe, and only then decides which
remaining plugins are worth executing. That ordering is what turns a
sixty-minute exhaustive sweep into a few minutes of targeted work.

Stages:

    normalize  -> canonical target
    recon      -> DNS, IP, HTTP, TLS (sequential; everything else depends on it)
    profile    -> technology fingerprint, framework, cloud, surface class
    select     -> technology-aware dynamic plugin selection
    execute    -> remaining plugins, concurrently, with adaptive concurrency
    correlate  -> cross-plugin enrichment and deduplication
    finalize   -> scoring, compliance mapping, risk roll-up
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable, Iterable
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from engine import events
from engine.cache import SharedCache
from engine.compliance import summarize as summarize_compliance
from engine.confidence import aggregate_risk
from engine.events import EventBus
from engine.fingerprint import Observation, classify_surface, detect_technologies
from engine.models import Finding, PluginOutcome, Surface, Technology
from engine.plugins import Plugin, PluginRegistry, ScanContext
from engine.selection import Plan, build_plan

LOG = logging.getLogger(__name__)

#: Plugins that must run first and in order: everything else profiles from them.
RECON_ORDER: tuple[str, ...] = ("dns", "ip", "http", "ssl")


def normalize_target(raw: str) -> str:
    """Reduce any user input to a bare hostname.

    Accepts URLs, hosts with ports, trailing dots and mixed case.
    """
    text = str(raw or "").strip()
    if not text:
        raise ValueError("A target is required.")
    if "://" in text:
        parsed = urlparse(text)
        text = parsed.netloc or parsed.path
    text = text.split("/", 1)[0]
    # Strip userinfo first: in "user:pass@host" the first colon belongs to the
    # credentials, not to a port, so splitting on it would discard the host.
    if "@" in text:
        text = text.rpartition("@")[2]
    if text.startswith("["):  # IPv6 literal
        text = text.partition("]")[0].lstrip("[")
    elif text.count(":") == 1:
        text = text.split(":", 1)[0]
    return text.strip().rstrip(".").lower()


@dataclass(slots=True)
class AdaptiveConcurrency:
    """Adjusts worker count in response to observed error rates.

    Additive increase on clean runs, multiplicative decrease when plugins start
    failing, so a struggling target is backed off rather than hammered.
    """

    minimum: int = 1
    maximum: int = 32
    current: int = 8
    _successes: int = 0
    _failures: int = 0

    def record(self, ok: bool) -> None:
        if ok:
            self._successes += 1
        else:
            self._failures += 1
        total = self._successes + self._failures
        if total < 4:
            return
        error_rate = self._failures / total
        if error_rate > 0.3:
            self.current = max(self.minimum, self.current // 2)
        elif error_rate < 0.05:
            self.current = min(self.maximum, self.current + 1)
        self._successes = self._failures = 0

    def clamp(self, requested: int) -> int:
        return max(self.minimum, min(self.maximum, requested))


@dataclass(slots=True)
class ScanResult:
    """Everything one target scan produced."""

    target: str
    started_at: float = field(default_factory=time.time)
    duration_ms: int = 0
    surface: Surface = Surface.UNKNOWN
    surface_reasons: list[str] = field(default_factory=list)
    technologies: list[Technology] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    outcomes: list[PluginOutcome] = field(default_factory=list)
    plan: Plan | None = None
    risk_score: float = 0.0
    cache_stats: dict[str, Any] = field(default_factory=dict)
    compliance: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def reported(self) -> list[Finding]:
        """Findings that cleared the confidence threshold."""
        return [item for item in self.findings if not item.suppressed]

    @property
    def suppressed(self) -> list[Finding]:
        return [item for item in self.findings if item.suppressed]

    def severity_counts(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.reported:
            counts[finding.severity.value] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "duration_ms": self.duration_ms,
            "surface": self.surface.value,
            "surface_reasons": list(self.surface_reasons),
            "risk_score": self.risk_score,
            "severity_counts": self.severity_counts(),
            "technologies": [tech.to_dict() for tech in self.technologies],
            "findings": [finding.to_dict() for finding in self.reported],
            "suppressed_findings": [finding.to_dict() for finding in self.suppressed],
            "plugins": [outcome.to_dict() for outcome in self.outcomes],
            "plan": self.plan.to_dict() if self.plan else {},
            "cache": self.cache_stats,
            "compliance": self.compliance,
            "errors": list(self.errors),
        }


class ScanPipeline:
    """Executes the staged pipeline for a single target."""

    def __init__(
        self,
        registry: PluginRegistry,
        *,
        bus: EventBus | None = None,
        cache: SharedCache | None = None,
        threads: int = 8,
        active: bool = False,
        force_all: bool = False,
        plugin_timeout: float = 300.0,
        legacy_factory: Callable[[type[Any], str], Any] | None = None,
    ) -> None:
        self.registry = registry
        self.bus = bus or EventBus()
        self.cache = cache or SharedCache()
        self.active = active
        self.force_all = force_all
        self.plugin_timeout = plugin_timeout
        self.legacy_factory = legacy_factory
        self.concurrency = AdaptiveConcurrency(current=max(1, threads), maximum=max(4, threads * 2))

    # -- stages ------------------------------------------------------------

    def _context(self, target: str, cancel_event: threading.Event | None) -> ScanContext:
        context = ScanContext(
            target=target,
            bus=self.bus,
            cache=self.cache,
            active=self.active,
            cancel_event=cancel_event,
        )
        if self.legacy_factory is not None:
            context.shared["legacy_factory"] = self.legacy_factory
        return context

    def _run_plugin(self, plugin: Plugin, context: ScanContext) -> PluginOutcome:
        outcome = plugin.execute(context)
        self.concurrency.record(outcome.status != "error")
        return outcome

    def _stage_recon(self, context: ScanContext, candidates: list[str], result: ScanResult) -> None:
        """Run the baseline plugins sequentially so later stages have data."""
        for name in RECON_ORDER:
            if name not in candidates or context.cancelled:
                continue
            plugin = self.registry.create(name)
            if plugin is None:
                continue
            outcome = self._run_plugin(plugin, context)
            result.outcomes.append(outcome)
            result.findings.extend(outcome.findings)
            if outcome.error:
                result.errors.append(f"{name}: {outcome.error}")

    def _stage_profile(self, context: ScanContext, result: ScanResult) -> None:
        """Build the technology profile and classify the attack surface."""
        observation = self._observation_from(context)
        technologies = detect_technologies(observation)
        surface, reasons = classify_surface(observation, technologies)

        context.technologies = technologies
        context.surface = surface
        result.technologies = technologies
        result.surface = surface
        result.surface_reasons = reasons

        for tech in technologies:
            self.bus.publish(
                events.TECHNOLOGY_DETECTED,
                {"name": tech.name, "category": tech.category, "confidence": tech.confidence},
                source="pipeline",
            )
        self.bus.publish(
            events.SURFACE_CLASSIFIED,
            {"surface": surface.value, "reasons": reasons},
            source="pipeline",
        )

    def _observation_from(self, context: ScanContext) -> Observation:
        """Assemble fingerprinter input from what the recon stage published."""
        legacy = context.shared.get("legacy_output", {})
        http = legacy.get("http", {}) if isinstance(legacy.get("http"), dict) else {}
        dns = legacy.get("dns", {}) if isinstance(legacy.get("dns"), dict) else {}
        ssl_data = legacy.get("ssl", {}) if isinstance(legacy.get("ssl"), dict) else {}

        headers = http.get("headers") or http.get("response_headers") or {}
        if not isinstance(headers, dict):
            headers = {}

        cookies = http.get("cookies") or ""
        if isinstance(cookies, (list, dict)):
            cookies = str(cookies)

        body = ""
        for key in ("body_sample", "html", "body", "title"):
            value = http.get(key)
            if isinstance(value, str) and value:
                body = value if len(value) > len(body) else body

        scripts = http.get("scripts") or http.get("javascript") or []
        if not isinstance(scripts, list):
            scripts = []

        endpoints = []
        for key in ("paths", "endpoints", "discovered"):
            value = (
                legacy.get("dirs", {}).get(key) if isinstance(legacy.get("dirs"), dict) else None
            )
            if isinstance(value, list):
                endpoints.extend(str(item) for item in value)

        return Observation(
            url=str(http.get("url") or context.target),
            status_code=int(http.get("status_code") or 0),
            headers={str(k): str(v) for k, v in headers.items()},
            cookies=str(cookies),
            body=body,
            scripts=[str(item) for item in scripts],
            endpoints=endpoints,
            dns_records=dns,
            tls=ssl_data,
        )

    def _stage_execute(self, context: ScanContext, plan: Plan, result: ScanResult) -> None:
        """Run the selected plugins concurrently with adaptive concurrency."""
        already_run = {outcome.plugin for outcome in result.outcomes}
        pending = [name for name in plan.selected if name not in already_run]
        if not pending:
            return

        workers = self.concurrency.clamp(min(self.concurrency.current, len(pending)))
        completed = 0
        total = len(pending)

        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="webosint") as pool:
            futures = {}
            for name in pending:
                plugin = self.registry.create(name)
                if plugin is None:
                    continue
                futures[pool.submit(self._run_plugin, plugin, context)] = name

            outstanding = set(futures)
            deadline = time.monotonic() + self.plugin_timeout * max(1, len(futures))

            while outstanding:
                done, outstanding = wait(outstanding, timeout=5.0, return_when=FIRST_COMPLETED)
                for future in done:
                    name = futures[future]
                    try:
                        outcome = future.result()
                    except Exception as exc:
                        outcome = PluginOutcome(
                            plugin=name, status="error", error=f"{type(exc).__name__}: {exc}"
                        )
                    result.outcomes.append(outcome)
                    result.findings.extend(outcome.findings)
                    if outcome.error:
                        result.errors.append(f"{name}: {outcome.error}")
                    completed += 1
                    self.bus.publish(
                        events.SCAN_PROGRESS,
                        {"completed": completed, "total": total, "plugin": name},
                        source="pipeline",
                    )

                if context.cancelled or time.monotonic() > deadline:
                    for future in outstanding:
                        future.cancel()
                        result.errors.append(f"{futures[future]}: abandoned (budget exceeded)")
                    break

    def _stage_finalize(self, result: ScanResult) -> None:
        """Deduplicate, roll up risk and map to control frameworks."""
        deduped: dict[str, Finding] = {}
        for finding in result.findings:
            key = finding.fingerprint
            existing = deduped.get(key)
            if existing is None:
                deduped[key] = finding
                continue
            # Same fact from two plugins: merge evidence, keep the worst severity.
            for evidence in finding.evidence:
                existing.add_evidence(evidence)
            if finding.severity.weight > existing.severity.weight:
                existing.severity = finding.severity

        result.findings = sorted(
            deduped.values(),
            key=lambda item: (-item.risk_score, item.severity.value, item.title),
        )
        result.risk_score = aggregate_risk(result.findings)
        result.compliance = summarize_compliance(list(result.reported)).to_dict()
        result.cache_stats = self.cache.summary()

    # -- entry point -------------------------------------------------------

    def scan(
        self,
        raw_target: str,
        *,
        candidates: Iterable[str] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> ScanResult:
        """Run the full pipeline for one target."""
        started = time.monotonic()
        target = normalize_target(raw_target)
        result = ScanResult(target=target)

        self.bus.publish(events.TARGET_NORMALIZED, {"target": target}, source="pipeline")

        context = self._context(target, cancel_event)
        names = list(candidates) if candidates is not None else self.registry.available_names()

        self._stage_recon(context, names, result)
        self._stage_profile(context, result)

        plan = build_plan(
            names,
            result.technologies,
            result.surface,
            active=self.active,
            force_all=self.force_all,
        )
        result.plan = plan

        self._stage_execute(context, plan, result)
        self._stage_finalize(result)

        result.duration_ms = int((time.monotonic() - started) * 1000)
        self.bus.publish(
            events.SCAN_COMPLETED,
            {
                "target": target,
                "findings": len(result.reported),
                "duration_ms": result.duration_ms,
            },
            source="pipeline",
        )
        return result


def scan_many(
    pipeline_factory: Callable[[], ScanPipeline],
    targets: Iterable[str],
    *,
    workers: int = 4,
) -> list[ScanResult]:
    """Scan many targets concurrently, each with its own pipeline and cache.

    A fresh pipeline per target keeps caches correctly scoped; the outer pool
    is what provides throughput for 100 or 1000 target inventories.
    """
    target_list = [item for item in targets if str(item).strip()]
    if not target_list:
        return []

    results: list[ScanResult] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(pipeline_factory().scan, target): target for target in target_list}
        for future, target in futures.items():
            try:
                results.append(future.result())
            except Exception as exc:
                failed = ScanResult(target=str(target))
                failed.errors.append(f"{type(exc).__name__}: {exc}")
                results.append(failed)
    return results
