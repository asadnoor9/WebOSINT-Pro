"""
WebOSINT Pro - Safe HTTP client

A thin wrapper around requests.Session that enforces the SafetyPolicy on every
single request, including redirects:

  * TLS verification is ON unless the run explicitly opted into --insecure-tls
  * per-request host/scheme validation (blocks localhost/private/reserved)
  * manual redirect following with re-validation of every hop (anti-SSRF)
  * hard timeouts, bounded retries with exponential backoff + jitter
  * response body size cap, so huge payloads are never buffered or stored
  * cancellation support through a shared threading.Event
"""

from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass
from typing import Any

import requests
from requests.adapters import HTTPAdapter

from core.safety import AuthorizationError, SafetyController, TargetBlockedError

DEFAULT_MAX_BODY_BYTES = 512 * 1024  # 512 KiB is plenty for fingerprinting
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})


_insecure_warning_silenced = False


def _silence_insecure_tls_warning() -> None:
    """Stop urllib3 warning once per request that TLS is unverified.

    Only reached when the operator explicitly passed --insecure-tls. The risk is
    already stated by the authorization banner and every finding from such a run
    is tagged UNTRUSTED, so repeating it thousands of times only buries the
    real output.
    """
    global _insecure_warning_silenced
    if _insecure_warning_silenced:
        return
    try:
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:  # pragma: no cover - urllib3 always ships with requests
        pass
    _insecure_warning_silenced = True


class RequestBlocked(Exception):
    """Raised when the safety layer refuses a request."""


class ScanCancelled(Exception):
    """Raised when a cancellation was requested mid-flight."""


@dataclass(slots=True)
class HttpConfig:
    timeout: float = 10.0
    retries: int = 2
    backoff: float = 0.4
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    max_redirects: int = 3
    user_agent: str = "WebOSINT-Pro/2.0 (+authorized-security-testing)"
    proxy: str | None = None
    pool_size: int = 10


class SafeSession:
    """Policy-enforcing HTTP session shared by every module."""

    def __init__(
        self,
        safety: SafetyController,
        config: HttpConfig | None = None,
        rate_limiter: Any = None,
        logger: Any = None,
        cancel_event: threading.Event | None = None,
    ) -> None:
        self.safety = safety
        self.cfg = config or HttpConfig()
        self.rate_limiter = rate_limiter
        self.logger = logger
        self.cancel_event = cancel_event or threading.Event()

        self._session = requests.Session()
        self._session.max_redirects = 1  # we follow redirects ourselves
        self._session.headers.clear()
        self._session.headers.update(
            {
                "User-Agent": self.cfg.user_agent,
                "Accept": "*/*",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "close",
            }
        )
        # TLS verification is the default and can only be disabled by policy.
        self._session.verify = self.safety.policy.verify_tls
        if not self._session.verify:
            _silence_insecure_tls_warning()
        if self.cfg.proxy:
            self._session.proxies = {"http": self.cfg.proxy, "https": self.cfg.proxy}

        adapter = HTTPAdapter(
            pool_connections=self.cfg.pool_size,
            pool_maxsize=self.cfg.pool_size,
            max_retries=0,
        )
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)

    # ── Properties ──────────────────────────────────────────────────────────────

    @property
    def verify_tls(self) -> bool:
        return self.safety.policy.verify_tls

    @property
    def headers(self) -> dict[str, str]:
        return dict(self._session.headers)

    def cancel(self) -> None:
        self.cancel_event.set()

    def close(self) -> None:
        self._session.close()

    # ── Verbs ───────────────────────────────────────────────────────────────────

    def get(self, url: str, **kw: Any) -> requests.Response | None:
        return self.request("GET", url, **kw)

    def head(self, url: str, **kw: Any) -> requests.Response | None:
        return self.request("HEAD", url, **kw)

    def post(self, url: str, **kw: Any) -> requests.Response | None:
        return self.request("POST", url, **kw)

    def options(self, url: str, **kw: Any) -> requests.Response | None:
        return self.request("OPTIONS", url, **kw)

    # ── Core ────────────────────────────────────────────────────────────────────

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response | None:
        """Perform a policy-checked request. Returns None on a handled failure."""
        if self.cancel_event.is_set():
            raise ScanCancelled("Scan cancelled")

        # Callers may not weaken TLS or redirect policy.
        kwargs.pop("verify", None)
        follow = bool(kwargs.pop("allow_redirects", True))
        timeout = float(kwargs.pop("timeout", self.cfg.timeout) or self.cfg.timeout)
        stream = kwargs.pop("stream", True)

        try:
            self.safety.check_url(url)
        except (TargetBlockedError, AuthorizationError) as exc:
            self._debug(f"blocked request: {exc}")
            raise RequestBlocked(str(exc)) from None

        current = url
        for hop in range(self.cfg.max_redirects + 1):
            response = self._send_with_retries(method, current, timeout, stream, **kwargs)
            if response is None:
                return None

            if not (follow and response.is_redirect and hop < self.cfg.max_redirects):
                return response

            location = response.headers.get("Location", "")
            if not location:
                return response
            next_url = requests.compat.urljoin(current, location)
            try:
                self.safety.check_url(next_url)
            except (TargetBlockedError, AuthorizationError) as exc:
                # SSRF guard: never follow a redirect out of the approved scope.
                self._debug(f"redirect blocked: {exc}")
                response.headers["X-WebOSINT-Redirect-Blocked"] = "1"
                return response
            response.close()
            current = next_url
            method = "GET" if response.status_code in (301, 302, 303) else method

        return None

    def _send_with_retries(
        self,
        method: str,
        url: str,
        timeout: float,
        stream: bool,
        **kwargs: Any,
    ) -> requests.Response | None:
        attempts = max(0, int(self.cfg.retries)) + 1
        for attempt in range(attempts):
            if self.cancel_event.is_set():
                raise ScanCancelled("Scan cancelled")
            if self.rate_limiter is not None:
                self.rate_limiter.acquire()

            started = time.perf_counter()
            try:
                response = self._session.request(
                    method,
                    url,
                    timeout=timeout,
                    allow_redirects=False,
                    stream=stream,
                    verify=self.verify_tls,
                    **kwargs,
                )
                self._cap_body(response)
                elapsed = (time.perf_counter() - started) * 1000
                self._log_request(method, url, response.status_code, elapsed)

                if response.status_code in RETRYABLE_STATUS and attempt < attempts - 1:
                    self._sleep_backoff(attempt, response)
                    continue
                return response

            except requests.exceptions.SSLError:
                # Never silently downgrade TLS: report and stop.
                self._debug(f"TLS verification failed for {url}")
                return None
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
                self._log_request(method, url, None, (time.perf_counter() - started) * 1000)
                if attempt < attempts - 1:
                    self._sleep_backoff(attempt)
                    continue
                return None
            except requests.exceptions.RequestException:
                return None
        return None

    def _cap_body(self, response: requests.Response) -> None:
        """Read at most max_body_bytes so oversized responses are never buffered."""
        limit = self.cfg.max_body_bytes
        try:
            content = response.raw.read(limit + 1, decode_content=True) or b""
        except Exception:
            content = b""
        truncated = len(content) > limit
        response._content = content[:limit]  # noqa: SLF001 - deliberate cap
        response._content_consumed = True  # noqa: SLF001
        if truncated:
            response.headers["X-WebOSINT-Truncated"] = "1"

    def _sleep_backoff(self, attempt: int, response: requests.Response | None = None) -> None:
        delay = self.cfg.backoff * (2**attempt) + random.uniform(0, 0.2)
        if response is not None:
            retry_after = response.headers.get("Retry-After")
            if retry_after and retry_after.isdigit():
                delay = max(delay, min(float(retry_after), 30.0))
        if self.cancel_event.wait(delay):
            raise ScanCancelled("Scan cancelled")

    # ── Logging ────────────────────────────────────────────────────────────────

    def _log_request(self, method: str, url: str, status: int | None, elapsed_ms: float) -> None:
        if self.logger is None:
            return
        request_log = getattr(self.logger, "request", None)
        if callable(request_log):
            request_log(method, url, status, elapsed_ms)

    def _debug(self, message: str) -> None:
        if self.logger is not None:
            self.logger.debug(message)
