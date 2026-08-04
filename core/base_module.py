"""
WebOSINT Pro - Base Module

All scan modules inherit from this. It is the only place modules may touch the
network, so every safety and privacy control is applied here:

  * TLS verification is ON by default; ``verify=False`` from a module is ignored
  * every request (and redirect hop) is validated against the SafetyPolicy
  * active/intrusive behaviour must be guarded with ``self.require_active()``
  * rate limiting, retry/backoff, timeouts and cancellation are centralized
  * findings are normalized, redacted and deduplicated
"""

from __future__ import annotations

import random
import threading
import time
from abc import ABC, abstractmethod
from typing import Any

import requests

from core.findings import Finding, FindingCollector, Severity
from core.netclient import HttpConfig, RequestBlocked, SafeSession, ScanCancelled
from core.redaction import DetailLevel, Redactor
from core.safe_exec import SafeRunner
from core.safety import AuthorizationError, SafetyController


class BaseModule(ABC):
    NAME: str = "base"
    DESCRIPTION: str = ""
    VERSION: str = "2.0.0"
    AUTHOR: str = "WebOSINT Pro"
    REQUIRES: list[str] = []
    TAGS: list[str] = []
    #: Passive modules only observe. Active modules send intrusive traffic and
    #: are skipped unless the operator passes --active.
    ACTIVE: bool = False

    def __init__(
        self,
        config: Any,
        logger: Any,
        rate_limiter: Any,
        safety: SafetyController | None = None,
        collector: FindingCollector | None = None,
        cancel_event: threading.Event | None = None,
    ) -> None:
        self.cfg = config
        self.logger = logger
        self.rl = rate_limiter
        self.target: str = config.target
        self.timeout: int = config.timeout
        self.retries: int = config.retries
        self.verbose: int = config.verbose
        self.findings: dict[str, Any] = {}

        self.safety: SafetyController = (
            safety or getattr(config, "safety", None) or (SafetyController())
        )
        self.policy = self.safety.policy
        self.cancel_event = cancel_event or threading.Event()

        self.redactor: Redactor = getattr(config, "redactor", None) or Redactor(
            level=DetailLevel.parse(getattr(config, "detail", "standard")),
            keep_raw=bool(getattr(config, "keep_raw", False)),
            extra_secrets=tuple(
                s
                for s in (getattr(config, "shodan_key", None), getattr(config, "nvd_key", None))
                if s
            ),
        )
        self.collector = collector or FindingCollector(
            self.redactor, untrusted=not self.policy.results_trusted
        )

        self.runner = SafeRunner(safety=self.safety, redactor=self.redactor)
        self.session = SafeSession(
            safety=self.safety,
            config=HttpConfig(
                timeout=float(config.timeout),
                retries=int(config.retries),
                user_agent=getattr(config, "user_agent", "WebOSINT-Pro/2.0"),
                proxy=getattr(config, "proxy", None),
                max_redirects=int(getattr(config, "max_redirects", 3)),
                pool_size=int(getattr(config, "threads", 10)),
            ),
            rate_limiter=rate_limiter,
            logger=logger,
            cancel_event=self.cancel_event,
        )

    # ── Abstract interface ───────────────────────────────────────────────────

    @abstractmethod
    def run(self) -> dict[str, Any]:
        """Execute the module and return a findings dict."""

    def teardown(self) -> None:
        try:
            self.session.close()
        except Exception:  # pragma: no cover - defensive cleanup
            pass

    # ── Safety helpers ───────────────────────────────────────────────────────

    @property
    def is_active_allowed(self) -> bool:
        return bool(self.policy.active)

    def require_active(self, what: str = "") -> None:
        """Guard an intrusive code path; raises unless --active was supplied."""
        self.policy.require_active(what or self.NAME)

    def skip_if_passive(self, what: str = "") -> bool:
        """Return True (and log once) when an active check must be skipped."""
        if self.policy.active:
            return False
        self.dlog(f"skipped active check '{what or self.NAME}' (passive mode)")
        return True

    # ── HTTP helpers ──────────────────────────────────────────────────────────

    def get(self, url: str, **kwargs: Any) -> requests.Response | None:
        return self._request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> requests.Response | None:
        return self._request("POST", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> requests.Response | None:
        return self._request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> requests.Response | None:
        return self._request("OPTIONS", url, **kwargs)

    def _request(self, method: str, url: str, **kwargs: Any) -> requests.Response | None:
        """All module traffic funnels through the policy-enforcing SafeSession."""
        kwargs.pop("verify", None)  # modules may never downgrade TLS
        try:
            return self.session.request(method, url, **kwargs)
        except RequestBlocked as exc:
            self.dlog(f"request refused by safety policy: {exc}")
            return None
        except AuthorizationError as exc:
            self.dlog(f"request refused: {exc}")
            return None
        except ScanCancelled:
            raise
        except Exception as exc:  # never leak internals
            self.dlog(f"request failed: {self.redactor.exception(exc)}")
            return None

    # ── Logging helpers ──────────────────────────────────────────────────────

    def log(self, msg: str, level: str = "info") -> None:
        getattr(self.logger, level)(f"[{self.NAME}] {self.redactor.text(msg)}")

    def vlog(self, msg: str) -> None:
        """INFO level — shown at -v."""
        self.logger.info(f"[{self.NAME}] {self.redactor.text(msg)}")

    def dlog(self, msg: str) -> None:
        """DEBUG level — shown at -vv."""
        self.logger.debug(f"[{self.NAME}] {self.redactor.text(msg)}")

    def tlog(self, msg: str) -> None:
        """TRACE level — shown at -vvv."""
        self.logger.trace(f"[{self.NAME}] {self.redactor.text(msg)}")

    # ── Finding helpers ──────────────────────────────────────────────────────

    def add_finding(self, key: str, value: Any, risk: str = "info") -> None:
        """Legacy dict-style finding. Redacted, stored and mirrored to the collector."""
        if value in (None, "", [], {}):
            return
        safe_value = self.redactor.data(value)
        self.findings[key] = safe_value
        self.logger.finding(self.NAME, key, safe_value, risk)

    def report(
        self,
        category: str,
        title: str,
        value: Any = "",
        severity: str | Severity = Severity.INFO,
        confidence: float = 0.5,
        evidence: str = "",
        tags: list[str] | None = None,
    ) -> Finding:
        """Emit a normalized, deduplicated finding with confidence + attribution."""
        finding = Finding(
            module=self.NAME,
            category=category,
            title=title,
            value=self.redactor.data(value),
            severity=Severity(severity) if isinstance(severity, str) else severity,
            confidence=confidence,
            evidence=self.redactor.text(evidence) if evidence else "",
            sources=[self.NAME],
            target=self.target,
            tags=list(tags or []),
        )
        return self.collector.add(finding)

    def set_risk(self, key: str, level: str) -> None:
        """Attach a risk tag to the legacy findings dict."""
        self.findings[f"_risk_{key}"] = level

    # ── Pacing helpers ───────────────────────────────────────────────────────

    def _sleep(self, seconds: float) -> None:
        if self.cancel_event.wait(max(0.0, seconds)):
            raise ScanCancelled("Scan cancelled")

    def stealth_delay(self) -> None:
        if getattr(self.cfg, "stealth", False) and self.cfg.delay > 0:
            self._sleep(self.cfg.delay + random.uniform(0, getattr(self.cfg, "jitter", 0.0)))

    def adaptive_delay(self, base_ms: float = 200) -> None:
        if self.cfg.delay > 0:
            self._sleep(base_ms / 1000.0 + random.uniform(0, 0.1))


# Backwards-compatible alias used by a few older modules.
def now_ms() -> float:
    return time.perf_counter() * 1000
