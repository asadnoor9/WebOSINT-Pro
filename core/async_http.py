"""
Async HTTP client primitives for high-volume recon modules.

The current modules are still synchronous. This client is intentionally small
and dependency-light so modules can migrate incrementally to asyncio/aiohttp
without changing the existing BaseModule contract.
"""

from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class AsyncHTTPResponse:
    url: str
    status: int
    headers: dict[str, str]
    text: str
    elapsed_ms: float


@dataclass(slots=True)
class AsyncHTTPConfig:
    timeout: float = 10.0
    retries: int = 2
    concurrency: int = 25
    proxy: str | None = None
    user_agent: str = "WebOSINT-Pro/1.0"
    jitter_min: float = 0.0
    jitter_max: float = 0.0
    headers: dict[str, str] = field(default_factory=dict)


class AsyncHTTPClient:
    """Semaphore-limited aiohttp client with retries and connection pooling."""

    def __init__(self, config: AsyncHTTPConfig, logger: Any = None) -> None:
        self.config = config
        self.logger = logger
        self._semaphore = asyncio.Semaphore(max(1, config.concurrency))
        self._session: Any = None

    async def __aenter__(self) -> AsyncHTTPClient:
        await self.start()
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        await self.close()

    async def start(self) -> None:
        if self._session is not None:
            return
        try:
            import aiohttp
        except ImportError as exc:
            raise RuntimeError("aiohttp is required for async scanning") from exc

        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        connector = aiohttp.TCPConnector(limit=max(1, self.config.concurrency), ssl=False)
        headers = {"User-Agent": self.config.user_agent, **self.config.headers}
        self._session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers=headers,
            raise_for_status=False,
        )

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    async def get(self, url: str, **kwargs: Any) -> AsyncHTTPResponse | None:
        return await self.request("GET", url, **kwargs)

    async def request(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> AsyncHTTPResponse | None:
        await self.start()
        assert self._session is not None

        async with self._semaphore:
            if self.config.jitter_max > 0:
                await asyncio.sleep(random.uniform(self.config.jitter_min, self.config.jitter_max))

            last_error: Exception | None = None
            for attempt in range(self.config.retries + 1):
                started = asyncio.get_running_loop().time()
                try:
                    proxy = kwargs.pop("proxy", self.config.proxy)
                    async with self._session.request(method, url, proxy=proxy, **kwargs) as resp:
                        text = await resp.text(errors="replace")
                        elapsed = (asyncio.get_running_loop().time() - started) * 1000
                        if self.logger:
                            self.logger.request(method, url, resp.status, elapsed)
                        return AsyncHTTPResponse(
                            url=str(resp.url),
                            status=resp.status,
                            headers=dict(resp.headers.items()),
                            text=text,
                            elapsed_ms=elapsed,
                        )
                except Exception as exc:
                    last_error = exc
                    if self.logger:
                        self.logger.debug(f"[async-http] {method} {url} failed: {exc}")
                    if attempt < self.config.retries:
                        await asyncio.sleep(min(5.0, 0.35 * (attempt + 1)))

            if self.logger and last_error:
                self.logger.debug(f"[async-http] exhausted retries for {url}: {last_error}")
            return None
