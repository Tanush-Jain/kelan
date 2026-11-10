from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any

import httpx
import structlog

log = structlog.get_logger()


@dataclass
class FetchResult:
    source: str
    status: str  # "success", "not_modified", "error", "skipped"
    records_count: int = 0
    duration_s: float = 0.0
    etag: str | None = None
    last_modified: str | None = None
    error_message: str | None = None


class BaseFetcher:
    source_name: str = "base"

    def __init__(
        self,
        timeout: float = 30.0,
        max_retries: int = 3,
        backoff_factor: float = 1.5,
        rate_limit_delay: float = 0.2,
    ) -> None:
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.rate_limit_delay = rate_limit_delay
        self._last_request_time = 0.0

    async def fetch(self, store: Any) -> FetchResult:
        raise NotImplementedError

    async def _rate_limit(self) -> None:
        elapsed = time.time() - self._last_request_time
        if elapsed < self.rate_limit_delay:
            await asyncio.sleep(self.rate_limit_delay - elapsed)
        self._last_request_time = time.time()

    async def request_with_retry(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        etag: str | None = None,
        last_modified: str | None = None,
    ) -> httpx.Response:
        req_headers = dict(headers or {})
        req_headers.setdefault("User-Agent", "Kelan-Intel/0.1 (+https://github.com/Tanush-Jain/kelan)")
        if etag:
            req_headers["If-None-Match"] = etag
        if last_modified:
            req_headers["If-Modified-Since"] = last_modified

        last_exc: Exception | None = None
        delay = 1.0

        for attempt in range(1, self.max_retries + 1):
            await self._rate_limit()
            try:
                resp = await client.request(
                    method,
                    url,
                    headers=req_headers,
                    params=params,
                    timeout=self.timeout,
                    follow_redirects=True,
                )
                if resp.status_code == 304:
                    return resp
                if resp.status_code == 429:
                    # Rate limited: check Retry-After
                    retry_after = float(resp.headers.get("Retry-After", delay))
                    log.warning(
                        "fetcher_rate_limited",
                        source=self.source_name,
                        attempt=attempt,
                        retry_after=retry_after,
                    )
                    await asyncio.sleep(min(retry_after, 10.0))
                    delay *= self.backoff_factor
                    continue
                resp.raise_for_status()
                return resp
            except httpx.HTTPStatusError as exc:
                last_exc = exc
                if exc.response.status_code in (401, 403, 404):
                    # Do not retry client auth/forbidden errors
                    raise
                if attempt < self.max_retries:
                    await asyncio.sleep(delay)
                    delay *= self.backoff_factor
            except (httpx.RequestError, asyncio.TimeoutError) as exc:
                last_exc = exc
                if attempt < self.max_retries:
                    await asyncio.sleep(delay)
                    delay *= self.backoff_factor

        if last_exc:
            raise last_exc
        raise RuntimeError(f"Request failed after {self.max_retries} attempts")

