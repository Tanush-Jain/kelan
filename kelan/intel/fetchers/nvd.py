from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from kelan.intel.db import IntelStore
from kelan.intel.fetchers.base import BaseFetcher, FetchResult
from kelan.intel.models import AdvisoryRecord, PackageRange

log = structlog.get_logger()

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NvdFetcher(BaseFetcher):
    source_name: str = "nvd"

    def __init__(self, api_key: str | None = None, **kw) -> None:
        key = api_key or os.getenv("KELAN_NVD_API_KEY") or os.getenv("NVD_API_KEY")
        # NVD rate limit: ~0.6s with API key, 6.0s without
        delay = 0.6 if key else 6.0
        kw.setdefault("rate_limit_delay", delay)
        super().__init__(**kw)
        self.api_key = key

    async def fetch(self, store: IntelStore, max_pages: int = 3) -> FetchResult:
        start_time = time.time()
        sync = store.get_sync_state(self.source_name)

        headers: dict[str, str] = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        now = datetime.now(UTC)
        params: dict[str, Any] = {
            "resultsPerPage": 500,
            "startIndex": 0,
        }

        # If sync exists, request incremental changes from last_sync_time
        if sync.last_sync_time:
            try:
                last_dt = datetime.fromisoformat(sync.last_sync_time)
                # NVD limits range to max 120 days
                if (now - last_dt).days > 119:
                    last_dt = now - timedelta(days=119)
                params["lastModStartDate"] = last_dt.strftime("%Y-%m-%dT%H:%M:%S.000")
                params["lastModEndDate"] = now.strftime("%Y-%m-%dT%H:%M:%S.000")
            except Exception:
                pass

        total_records = 0

        try:
            async with httpx.AsyncClient() as client:
                start_index = 0
                for _ in range(max_pages):
                    params["startIndex"] = start_index
                    resp = await self.request_with_retry(
                        client,
                        "GET",
                        NVD_API_URL,
                        headers=headers,
                        params=params,
                    )

                    data = resp.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    if not vulnerabilities:
                        break

                    for item in vulnerabilities:
                        adv = self._parse_nvd_item(item.get("cve", {}))
                        if adv:
                            store.upsert_advisory(adv)
                            total_records += 1

                    total_results = data.get("totalResults", 0)
                    start_index += len(vulnerabilities)
                    if start_index >= total_results:
                        break

            return FetchResult(
                source=self.source_name,
                status="success",
                records_count=total_records,
                duration_s=time.time() - start_time,
            )

        except Exception as exc:
            log.warning("nvd_fetch_failed", error=str(exc))
            return FetchResult(
                source=self.source_name,
                status="error",
                duration_s=time.time() - start_time,
                error_message=str(exc),
            )

    @staticmethod
    def _parse_nvd_item(cve: dict) -> AdvisoryRecord | None:
        cve_id = cve.get("id")
        if not cve_id:
            return None

        # Description
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        # Metrics / CVSS
        metrics = cve.get("metrics", {})
        cvss_score = None
        cvss_vec = None
        severity_str = "MEDIUM"

        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                m = metrics[key][0]
                cvss_data = m.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_vec = cvss_data.get("vectorString")
                if "baseSeverity" in cvss_data:
                    severity_str = str(cvss_data["baseSeverity"]).upper()
                break

        # Packages from CPEs
        packages: list[PackageRange] = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe_str = match.get("criteria", "")
                    # Example: cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*
                    parts = cpe_str.split(":")
                    if len(parts) >= 5 and parts[2] == "a":
                        product = parts[4]
                        intro = match.get("versionStartIncluding", "0")
                        fixed = match.get("versionEndExcluding")
                        packages.append(
                            PackageRange(
                                ecosystem="all",
                                package_name=product,
                                introduced=intro,
                                fixed=fixed,
                            )
                        )

        return AdvisoryRecord(
            id=cve_id,
            source="nvd",
            title=f"NVD: {cve_id}",
            description=desc,
            cvss_score=cvss_score,
            cvss_vector=cvss_vec,
            severity=severity_str,
            published_at=cve.get("published"),
            modified_at=cve.get("lastModified"),
            aliases=[cve_id],
            packages=packages,
            raw_payload=json.dumps(cve),
        )

