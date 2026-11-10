from __future__ import annotations

import io
import json
import time
import zipfile

import httpx
import structlog

from kelan.intel.db import IntelStore
from kelan.intel.fetchers.base import BaseFetcher, FetchResult
from kelan.intel.models import AdvisoryRecord, PackageRange

log = structlog.get_logger()

OSV_ECOSYSTEMS = ["PyPI", "npm", "crates.io", "Go", "Maven"]
OSV_BULK_URL_TEMPLATE = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"


class OsvFetcher(BaseFetcher):
    source_name: str = "osv"

    def __init__(self, ecosystems: list[str] | None = None, **kw) -> None:
        super().__init__(**kw)
        self.ecosystems = ecosystems or OSV_ECOSYSTEMS

    async def fetch(self, store: IntelStore) -> FetchResult:
        start_time = time.time()
        sync = store.get_sync_state(self.source_name)
        total_records = 0
        last_etag = sync.etag
        last_mod = sync.last_modified

        try:
            async with httpx.AsyncClient() as client:
                for eco in self.ecosystems:
                    url = OSV_BULK_URL_TEMPLATE.format(ecosystem=eco)
                    try:
                        resp = await self.request_with_retry(
                            client,
                            "GET",
                            url,
                            etag=sync.etag,
                            last_modified=sync.last_modified,
                        )
                    except httpx.HTTPStatusError as exc:
                        if exc.response.status_code == 404:
                            continue
                        raise

                    if resp.status_code == 304:
                        continue

                    last_etag = resp.headers.get("ETag") or last_etag
                    last_mod = resp.headers.get("Last-Modified") or last_mod

                    # Unzip in-memory
                    try:
                        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
                            for name in zf.namelist():
                                if not name.endswith(".json"):
                                    continue
                                try:
                                    raw_text = zf.read(name).decode("utf-8", errors="replace")
                                    item = json.loads(raw_text)
                                    adv = self._parse_osv_item(item, raw_text, default_eco=eco)
                                    if adv:
                                        store.upsert_advisory(adv)
                                        total_records += 1
                                except Exception:
                                    continue
                    except zipfile.BadZipFile:
                        continue

            return FetchResult(
                source=self.source_name,
                status="success" if total_records > 0 else ("not_modified" if sync.records_count > 0 else "success"),
                records_count=total_records or sync.records_count,
                duration_s=time.time() - start_time,
                etag=last_etag,
                last_modified=last_mod,
            )

        except Exception as exc:
            log.warning("osv_fetch_failed", error=str(exc))
            return FetchResult(
                source=self.source_name,
                status="error",
                duration_s=time.time() - start_time,
                error_message=str(exc),
            )

    @staticmethod
    def _parse_osv_item(data: dict, raw_payload: str, default_eco: str) -> AdvisoryRecord | None:
        adv_id = data.get("id")
        if not adv_id:
            return None

        title = data.get("summary") or ""
        desc = data.get("details") or ""
        published_at = data.get("published")
        modified_at = data.get("modified")
        aliases = [str(a) for a in data.get("aliases", []) if a]

        # Severity / CVSS
        cvss_score = None
        cvss_vec = None
        severity_str = "MEDIUM"

        db_spec = data.get("database_specific") or {}
        if "severity" in db_spec:
            severity_str = str(db_spec["severity"]).upper()

        for s in data.get("severity", []):
            if s.get("type") in ("CVSS_V3", "CVSS_V2"):
                score_str = s.get("score")
                if score_str and score_str.startswith("CVSS:"):
                    cvss_vec = score_str

        # Affected packages and version ranges
        packages: list[PackageRange] = []
        for aff in data.get("affected", []):
            pkg_info = aff.get("package") or {}
            pkg_name = pkg_info.get("name")
            if not pkg_name:
                continue
            eco = pkg_info.get("ecosystem") or default_eco
            versions = [str(v) for v in aff.get("versions", [])]

            ranges = aff.get("ranges", [])
            if ranges:
                for r in ranges:
                    intro = "0"
                    fixed = None
                    for ev in r.get("events", []):
                        if "introduced" in ev:
                            intro = ev["introduced"]
                        if "fixed" in ev:
                            fixed = ev["fixed"]
                    packages.append(
                        PackageRange(
                            ecosystem=eco,
                            package_name=pkg_name,
                            introduced=intro,
                            fixed=fixed,
                            versions=versions,
                        )
                    )
            else:
                packages.append(
                    PackageRange(
                        ecosystem=eco,
                        package_name=pkg_name,
                        introduced="0",
                        fixed=None,
                        versions=versions,
                    )
                )

        return AdvisoryRecord(
            id=adv_id,
            source="osv",
            title=title,
            description=desc,
            cvss_score=cvss_score,
            cvss_vector=cvss_vec,
            severity=severity_str,
            published_at=published_at,
            modified_at=modified_at,
            aliases=aliases,
            packages=packages,
            raw_payload=raw_payload,
        )

