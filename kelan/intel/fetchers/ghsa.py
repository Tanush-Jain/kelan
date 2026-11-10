from __future__ import annotations

import json
import os
import re
import time
from typing import Any

import httpx
import structlog

from kelan.intel.db import IntelStore
from kelan.intel.fetchers.base import BaseFetcher, FetchResult
from kelan.intel.models import AdvisoryRecord, PackageRange

log = structlog.get_logger()

GHSA_API_URL = "https://api.github.com/advisories"

ECOSYSTEM_MAP = {
    "pip": "pypi",
    "pypi": "pypi",
    "npm": "npm",
    "cargo": "crates.io",
    "crates.io": "crates.io",
    "go": "go",
    "maven": "maven",
    "rubygems": "rubygems",
    "nuget": "nuget",
}


def _parse_ghsa_range(range_str: str | None, patched: str | None) -> tuple[str, str | None]:
    """Parse GHSA vulnerable_version_range e.g. '>= 1.0.0, < 1.2.3' or '< 1.2.3'."""
    intro = "0"
    fixed = patched

    if range_str:
        # Check for introduced: >= X or > X
        m_intro = re.search(r"(?:>=|>)\s*([0-9][A-Za-z0-9._-]*)", range_str)
        if m_intro:
            intro = m_intro.group(1)

        # Check for fixed: < X or <= X
        if not fixed:
            m_fixed = re.search(r"<\s*([0-9][A-Za-z0-9._-]*)", range_str)
            if m_fixed:
                fixed = m_fixed.group(1)

    return intro, fixed


class GhsaFetcher(BaseFetcher):
    source_name: str = "ghsa"

    def __init__(self, token: str | None = None, **kw) -> None:
        super().__init__(**kw)
        self.token = token or os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")

    async def fetch(self, store: IntelStore, max_pages: int = 5) -> FetchResult:
        start_time = time.time()
        sync = store.get_sync_state(self.source_name)

        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        params: dict[str, Any] = {
            "per_page": 100,
            "direction": "desc",
            "sort": "updated",
        }
        if sync.last_sync_time:
            params["updated"] = f">={sync.last_sync_time}"

        total_records = 0
        new_last_mod = sync.last_modified
        new_etag = sync.etag

        try:
            async with httpx.AsyncClient() as client:
                for page in range(1, max_pages + 1):
                    params["page"] = page
                    resp = await self.request_with_retry(
                        client,
                        "GET",
                        GHSA_API_URL,
                        headers=headers,
                        params=params,
                        etag=sync.etag if page == 1 else None,
                        last_modified=sync.last_modified if page == 1 else None,
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

                    if page == 1:
                        new_etag = resp.headers.get("ETag") or sync.etag
                        new_last_mod = resp.headers.get("Last-Modified") or sync.last_modified

                    items = resp.json()
                    if not items or not isinstance(items, list):
                        break

                    for item in items:
                        adv = self._parse_ghsa_item(item)
                        if adv:
                            store.upsert_advisory(adv)
                            total_records += 1

                    if len(items) < 100:
                        break

            return FetchResult(
                source=self.source_name,
                status="success",
                records_count=total_records,
                duration_s=time.time() - start_time,
                etag=new_etag,
                last_modified=new_last_mod,
            )

        except Exception as exc:
            log.warning("ghsa_fetch_failed", error=str(exc))
            return FetchResult(
                source=self.source_name,
                status="error",
                duration_s=time.time() - start_time,
                error_message=str(exc),
            )

    @staticmethod
    def _parse_ghsa_item(item: dict) -> AdvisoryRecord | None:
        ghsa_id = item.get("ghsa_id")
        if not ghsa_id:
            return None

        cve_id = item.get("cve_id")
        title = item.get("summary") or ""
        desc = item.get("description") or ""
        sev_str = str(item.get("severity") or "MEDIUM").upper()

        cvss = item.get("cvss") or {}
        cvss_score = cvss.get("score")
        cvss_vec = cvss.get("vector_string")

        aliases = []
        if cve_id:
            aliases.append(cve_id)

        packages: list[PackageRange] = []
        for v in item.get("vulnerabilities", []):
            pkg_info = v.get("package") or {}
            raw_eco = pkg_info.get("ecosystem", "").lower()
            eco = ECOSYSTEM_MAP.get(raw_eco, raw_eco)
            pkg_name = pkg_info.get("name")
            if not pkg_name:
                continue

            v_range = v.get("vulnerable_version_range")
            patched_info = v.get("first_patched_version") or {}
            patched_ver = patched_info.get("identifier") if isinstance(patched_info, dict) else None

            intro, fixed = _parse_ghsa_range(v_range, patched_ver)
            packages.append(
                PackageRange(
                    ecosystem=eco,
                    package_name=pkg_name,
                    introduced=intro,
                    fixed=fixed,
                )
            )

        return AdvisoryRecord(
            id=ghsa_id,
            source="ghsa",
            title=title,
            description=desc,
            cvss_score=cvss_score,
            cvss_vector=cvss_vec,
            severity=sev_str,
            published_at=item.get("published_at"),
            modified_at=item.get("updated_at"),
            aliases=aliases,
            packages=packages,
            raw_payload=json.dumps(item),
        )

