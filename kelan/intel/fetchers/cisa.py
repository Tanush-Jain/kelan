from __future__ import annotations

import json
import time

import httpx
import structlog

from kelan.intel.db import IntelStore
from kelan.intel.fetchers.base import BaseFetcher, FetchResult

log = structlog.get_logger()

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CisaKevFetcher(BaseFetcher):
    source_name: str = "cisa_kev"

    async def fetch(self, store: IntelStore) -> FetchResult:
        start_time = time.time()
        sync = store.get_sync_state(self.source_name)

        try:
            async with httpx.AsyncClient() as client:
                resp = await self.request_with_retry(
                    client,
                    "GET",
                    CISA_KEV_URL,
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

                data = resp.json()
                vulnerabilities = data.get("vulnerabilities", [])
                count = 0
                for item in vulnerabilities:
                    cve_id = item.get("cveID")
                    if not cve_id:
                        continue
                    date_added = item.get("dateAdded")
                    vuln_name = item.get("vulnerabilityName") or item.get("shortDescription", "")
                    desc = item.get("shortDescription") or item.get("notes", "")
                    raw_str = json.dumps(item)

                    store.set_kev_status(
                        cve=cve_id,
                        is_kev=True,
                        date_added=date_added,
                        title=vuln_name,
                        description=desc,
                        raw_payload=raw_str,
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
            log.warning("cisa_kev_fetch_failed", error=str(exc))
            return FetchResult(
                source=self.source_name,
                status="error",
                duration_s=time.time() - start_time,
                error_message=str(exc),
            )

