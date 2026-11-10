from __future__ import annotations

import csv
import gzip
import io
import time
from datetime import UTC, datetime

import httpx
import structlog

from kelan.intel.db import IntelStore
from kelan.intel.fetchers.base import BaseFetcher, FetchResult

log = structlog.get_logger()

EPSS_CURRENT_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


class EpssFetcher(BaseFetcher):
    source_name: str = "epss"

    async def fetch(self, store: IntelStore) -> FetchResult:
        start_time = time.time()
        sync = store.get_sync_state(self.source_name)

        try:
            async with httpx.AsyncClient() as client:
                resp = await self.request_with_retry(
                    client,
                    "GET",
                    EPSS_CURRENT_URL,
                    etag=sync.etag,
                    last_modified=sync.last_modified,
                )

                if resp.status_code == 304:
                    return FetchResult(
                        source=self.source_name,
                        status="not_modified",
                        records_count=sync.records_count,
                        duration_s=time.time() - start_time,
                        etag=sync.etag,
                        last_modified=sync.last_modified,
                    )

                content = resp.content
                # Decompress gzip if needed
                if content[:2] == b"\x1f\x8b":
                    decompressed = gzip.decompress(content).decode("utf-8", errors="replace")
                else:
                    decompressed = content.decode("utf-8", errors="replace")

                lines = decompressed.splitlines()
                score_date = datetime.now(UTC).strftime("%Y-%m-%d")

                # Check comment header for score_date (e.g. #model_version:v2023.03.01,score_date:2026-11-09T00:00:00+0000)
                data_lines = []
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith("#"):
                        if "score_date:" in line:
                            parts = line.split("score_date:")
                            if len(parts) > 1:
                                raw_date = parts[1].split(",")[0].strip()
                                score_date = raw_date[:10]
                        continue
                    data_lines.append(line)

                reader = csv.reader(io.StringIO("\n".join(data_lines)))
                header = next(reader, None)
                count = 0

                # header should be ['cve', 'epss', 'percentile']
                for row in reader:
                    if len(row) < 2:
                        continue
                    cve = row[0].strip()
                    if not cve.upper().startswith("CVE-"):
                        continue
                    try:
                        epss_val = float(row[1].strip())
                        pct_val = float(row[2].strip()) if len(row) > 2 else None
                    except ValueError:
                        continue

                    store.record_epss_score(
                        cve=cve,
                        score=epss_val,
                        percentile=pct_val,
                        date_str=score_date,
                    )
                    count += 1

                new_etag = resp.headers.get("ETag") or sync.etag
                new_last_mod = resp.headers.get("Last-Modified") or sync.last_modified

                return FetchResult(
                    source=self.source_name,
                    status="success",
                    records_count=count,
                    duration_s=time.time() - start_time,
                    etag=new_etag,
                    last_modified=new_last_mod,
                )

        except Exception as exc:
            log.warning("epss_fetch_failed", error=str(exc))
            return FetchResult(
                source=self.source_name,
                status="error",
                duration_s=time.time() - start_time,
                error_message=str(exc),
            )

