"""Rate-limited, scope-aware async HTTP client.

Wraps httpx.AsyncClient with:
  * a global rate limit (token-interval) and concurrency cap,
  * scope enforcement on every request,
  * request counting for reporting.

All scanners share one client per scan so the rate limit is global.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Optional

import httpx

from app.config import settings
from app.core.scope import Scope


@dataclass
class HttpClient:
    scope: Scope
    _client: Optional[httpx.AsyncClient] = None
    _sem: Optional[asyncio.Semaphore] = None
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _last_request_ts: float = 0.0
    request_count: int = 0

    async def __aenter__(self) -> "HttpClient":
        self._sem = asyncio.Semaphore(settings.max_concurrency)
        self._client = httpx.AsyncClient(
            timeout=settings.request_timeout,
            verify=settings.verify_tls,
            follow_redirects=True,
            headers={"User-Agent": settings.user_agent},
        )
        return self

    async def __aexit__(self, *exc) -> None:
        if self._client:
            await self._client.aclose()

    async def _throttle(self) -> None:
        """Enforce a minimum interval between request starts (global)."""
        interval = settings.min_request_interval
        if interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            wait = self._last_request_ts + interval - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request_ts = time.monotonic()

    async def request(self, method: str, url: str, **kwargs) -> Optional[httpx.Response]:
        self.scope.assert_allowed(url)
        assert self._client is not None and self._sem is not None
        async with self._sem:
            await self._throttle()
            self.request_count += 1
            try:
                return await self._client.request(method, url, **kwargs)
            except httpx.HTTPError:
                return None

    async def get(self, url: str, **kwargs) -> Optional[httpx.Response]:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> Optional[httpx.Response]:
        return await self.request("POST", url, **kwargs)
