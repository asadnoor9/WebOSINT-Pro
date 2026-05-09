"""
WebOSINT Pro - Base Module
All scan modules inherit from this. Provides:
  • Rate-limited, retry-aware HTTP helpers
  • Per-request verbose logging (-vv logs every request)
  • Raw dump at -vvv
"""

import time
import random
import requests
import urllib3
from abc import ABC, abstractmethod

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class BaseModule(ABC):
    NAME        = 'base'
    DESCRIPTION = ''

    def __init__(self, config, logger, rate_limiter):
        self.cfg          = config
        self.logger       = logger
        self.rl           = rate_limiter
        self.target       = config.target
        self.timeout      = config.timeout
        self.retries      = config.retries
        self.verbose      = config.verbose
        self.findings     = {}

        self.session = requests.Session()
        self.session.headers['User-Agent'] = config.user_agent
        if config.proxy:
            self.session.proxies = {'http': config.proxy, 'https': config.proxy}
        self.session.verify = False

    # ── Abstract ─────────────────────────────────────────────────────────
    @abstractmethod
    def run(self) -> dict:
        pass

    # ── HTTP helpers ──────────────────────────────────────────────────────
    def get(self, url: str, **kwargs) -> requests.Response | None:
        return self._request('GET', url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response | None:
        return self._request('POST', url, **kwargs)

    def _request(self, method: str, url: str, **kwargs) -> requests.Response | None:
        self.rl.acquire()
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('verify', False)
        kwargs.setdefault('allow_redirects', True)

        for attempt in range(self.retries + 1):
            t0 = time.perf_counter()
            try:
                r = self.session.request(method, url, **kwargs)
                elapsed = (time.perf_counter() - t0) * 1000

                # -vv: every request
                self.logger.request(method, url, r.status_code, elapsed)

                # -vvv: raw response headers + body snippet
                if self.verbose >= 3:
                    self.logger.raw('resp-headers', dict(r.headers))
                    self.logger.raw('resp-body',    r.text[:400])

                return r

            except requests.exceptions.SSLError as e:
                elapsed = (time.perf_counter() - t0) * 1000
                self.logger.request(method, url, None, elapsed)
                self.log(f"SSL error {url}: {e}", 'debug')
                # retry without verify
                kwargs['verify'] = False
                if attempt < self.retries:
                    time.sleep(0.4 * (attempt + 1))

            except requests.exceptions.ConnectionError as e:
                elapsed = (time.perf_counter() - t0) * 1000
                self.logger.request(method, url, None, elapsed)
                self.log(f"Connection error {url}: {e}", 'debug')
                if attempt < self.retries:
                    time.sleep(0.5 * (attempt + 1))

            except requests.exceptions.Timeout:
                elapsed = (time.perf_counter() - t0) * 1000
                self.logger.request(method, url, None, elapsed)
                self.log(f"Timeout {url} (attempt {attempt+1})", 'debug')
                if attempt < self.retries:
                    time.sleep(0.3)

            except Exception as e:
                self.log(f"Request error {url}: {e}", 'debug')
                break

        return None

    # ── Logging helpers ───────────────────────────────────────────────────
    def log(self, msg: str, level: str = 'info'):
        getattr(self.logger, level)(f"[{self.NAME}] {msg}")

    def vlog(self, msg: str):
        """Info-level: shown at -v."""
        self.logger.info(f"[{self.NAME}] {msg}")

    def dlog(self, msg: str):
        """Debug-level: shown at -vv."""
        self.logger.debug(f"[{self.NAME}] {msg}")

    def tlog(self, msg: str):
        """Trace-level: shown at -vvv."""
        self.logger.trace(f"[{self.NAME}] {msg}")

    def add_finding(self, key: str, value, risk: str = 'info'):
        if value:
            self.findings[key] = {'value': value, 'risk': risk}
            self.logger.finding(self.NAME, key, value, risk)

    # ── Stealth helpers ───────────────────────────────────────────────────
    def stealth_delay(self):
        if self.cfg.stealth:
            delay = self.cfg.delay + random.uniform(0, self.cfg.jitter)
            self.tlog(f"stealth delay {delay:.2f}s")
            time.sleep(delay)
