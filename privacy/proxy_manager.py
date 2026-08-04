"""
WebOSINT Pro - Proxy Manager
Manages HTTP/SOCKS proxy configuration for authorized lab scanning.

Supports:
  • Single proxy URL
  • Proxy rotation from list
  • Proxy health checking
  • Per-scheme proxy mapping (http vs https)
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

import requests

PROXY_TEST_URL = "https://httpbin.org/ip"
PROXY_TIMEOUT = 8


@dataclass
class ProxyEntry:
    url: str
    scheme: str = "http"
    alive: bool = True
    latency_ms: float = 0.0

    @property
    def parsed(self) -> urlparse:
        return urlparse(self.url)

    def to_requests_dict(self) -> dict[str, str]:
        return {"http": self.url, "https": self.url}


class ProxyManager:
    """
    Manages a pool of proxies for privacy-aware scanning in lab environments.
    Falls back gracefully to direct connection if no proxies configured.
    """

    def __init__(
        self,
        proxy_url: str | None = None,
        proxy_list: list[str] | None = None,
        rotate: bool = False,
        verify_proxies: bool = False,
    ) -> None:
        self._proxies: list[ProxyEntry] = []
        self._rotate = rotate
        self._idx = 0

        if proxy_url:
            self._proxies.append(ProxyEntry(url=proxy_url))
        if proxy_list:
            for url in proxy_list:
                if url not in [p.url for p in self._proxies]:
                    self._proxies.append(ProxyEntry(url=url))

        if verify_proxies and self._proxies:
            self._check_proxies()

    # ── Public API ───────────────────────────────────────────────────────────────

    def get_proxy_dict(self) -> dict[str, str] | None:
        """Return the next proxy dict for use in requests.Session.proxies."""
        alive = [p for p in self._proxies if p.alive]
        if not alive:
            return None

        if self._rotate:
            proxy = alive[self._idx % len(alive)]
            self._idx += 1
        else:
            proxy = alive[0]

        return proxy.to_requests_dict()

    def apply_to_session(self, session: requests.Session) -> None:
        """Apply proxy settings to an existing requests.Session."""
        proxy_dict = self.get_proxy_dict()
        if proxy_dict:
            session.proxies.update(proxy_dict)

    @property
    def has_proxies(self) -> bool:
        return bool(self._proxies)

    @property
    def alive_count(self) -> int:
        return sum(1 for p in self._proxies if p.alive)

    def status(self) -> dict:
        return {
            "total": len(self._proxies),
            "alive": self.alive_count,
            "rotate": self._rotate,
            "proxies": [
                {"url": p.url, "alive": p.alive, "latency_ms": p.latency_ms} for p in self._proxies
            ],
        }

    # ── Health checking ──────────────────────────────────────────────────────────

    def _check_proxies(self) -> None:
        """Test each proxy against a known endpoint. Mark dead proxies."""
        for proxy in self._proxies:
            try:
                import time

                t0 = time.perf_counter()
                r = requests.get(
                    PROXY_TEST_URL,
                    proxies=proxy.to_requests_dict(),
                    timeout=PROXY_TIMEOUT,
                )
                proxy.latency_ms = (time.perf_counter() - t0) * 1000
                proxy.alive = r.status_code == 200
            except Exception:
                proxy.alive = False
