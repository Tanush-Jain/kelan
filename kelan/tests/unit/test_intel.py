from __future__ import annotations

import gzip
import io
import json
import tempfile
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

import httpx
import pytest

from kelan.core.finding import FindingSet, Severity
from kelan.core.plugin import ScanConfig, ScanContext, ScanTarget, ScopeKind
from kelan.intel.bundle import (
    BundleVerificationError,
    export_bundle,
    import_bundle,
)
from kelan.intel.cli import cmd_export_bundle, cmd_intel, cmd_update
from kelan.intel.db import IntelStore
from kelan.intel.fetchers.cisa import CisaKevFetcher
from kelan.intel.fetchers.epss import EpssFetcher
from kelan.intel.fetchers.ghsa import GhsaFetcher
from kelan.intel.fetchers.nvd import NvdFetcher
from kelan.intel.fetchers.osv import OsvFetcher
from kelan.intel.models import AdvisoryRecord, PackageRange, PackageSpec, SyncState
from kelan.intel.trending import show_search, show_trending
from kelan.intel.updater import IntelUpdater
from kelan.intel.version_match import compare_versions, is_version_vulnerable
from kelan.plugins.sca import ScaPlugin


# ============================================================================
# 1. Version Comparison and Range Matching Tests
# ============================================================================

def test_compare_versions_ecosystems():
    assert compare_versions("1.2.3", "1.2.4") == -1
    assert compare_versions("1.2.4", "1.2.3") == 1
    assert compare_versions("v1.2.3", "1.2.3") == 0
    assert compare_versions("2.0.0-rc1", "2.0.0") == -1
    # Maven style
    assert compare_versions("2.14.1.Final", "2.15.0") == -1
    assert compare_versions("1.0", "1.0.0") == 0


def test_is_version_vulnerable():
    # Inside [1.0.0, 1.5.0)
    assert is_version_vulnerable("1.2.0", introduced="1.0.0", fixed="1.5.0") is True
    # Below introduced
    assert is_version_vulnerable("0.9.0", introduced="1.0.0", fixed="1.5.0") is False
    # At fixed version (patched)
    assert is_version_vulnerable("1.5.0", introduced="1.0.0", fixed="1.5.0") is False
    # Above fixed version
    assert is_version_vulnerable("1.6.0", introduced="1.0.0", fixed="1.5.0") is False
    # No fixed version (unpatched)
    assert is_version_vulnerable("2.0.0", introduced="1.0.0", fixed=None) is True
    # Introduced "0"
    assert is_version_vulnerable("0.5.0", introduced="0", fixed="1.0.0") is True
    # Specific versions list
    assert is_version_vulnerable("1.2.3", specific_versions=["1.2.3", "1.2.4"]) is True
    assert is_version_vulnerable("1.2.5", specific_versions=["1.2.3", "1.2.4"]) is False


# ============================================================================
# 2. Local SQLite Store and FTS5 Tests
# ============================================================================

def test_intel_store_crud_and_fts():
    store = IntelStore(":memory:")
    adv = AdvisoryRecord(
        id="CVE-2023-45678",
        source="nvd",
        title="Path Traversal in web-framework",
        description="Arbitrary file read via improper neutralization of special elements",
        cvss_score=8.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        severity="HIGH",
        epss_score=0.45,
        epss_percentile=0.92,
        epss_date="2026-11-09",
        is_kev=True,
        kev_date_added="2026-11-09",
        aliases=["GHSA-abcd-1234-wxyz"],
        packages=[
            PackageRange(ecosystem="pypi", package_name="web-framework", introduced="1.0.0", fixed="1.4.2")
        ],
    )
    store.upsert_advisory(adv)

    # Retrieval
    retrieved = store.get_advisory("CVE-2023-45678")
    assert retrieved is not None
    assert retrieved.id == "CVE-2023-45678"
    assert retrieved.cvss_score == 8.5
    assert retrieved.is_kev is True
    assert "GHSA-abcd-1234-wxyz" in retrieved.aliases
    assert len(retrieved.packages) == 1

    # Alias retrieval
    by_alias = store.get_advisory("GHSA-abcd-1234-wxyz")
    assert by_alias is not None
    assert by_alias.id == "CVE-2023-45678"

    # FTS5 search
    res1 = store.search("traversal")
    assert len(res1) == 1
    assert res1[0].id == "CVE-2023-45678"

    res2 = store.search("web-framework")
    assert len(res2) == 1
    assert res2[0].id == "CVE-2023-45678"

    # Match package
    v_spec = PackageSpec(name="web-framework", version="1.2.0", ecosystem="pypi")
    s_spec = PackageSpec(name="web-framework", version="1.5.0", ecosystem="pypi")
    matches = store.match_packages([v_spec, s_spec])
    assert len(matches) == 1
    assert matches[0][0].version == "1.2.0"
    assert matches[0][1].id == "CVE-2023-45678"

    store.close()


def test_intel_store_epss_and_kev_updates():
    store = IntelStore(":memory:")
    adv = AdvisoryRecord(
        id="CVE-2024-0001",
        source="nvd",
        title="Test Vuln",
        packages=[PackageRange(ecosystem="npm", package_name="test-lib", introduced="0", fixed="1.0.0")],
    )
    store.upsert_advisory(adv)

    # Update EPSS score
    store.record_epss_score("CVE-2024-0001", score=0.88, percentile=0.98, date_str="2026-11-09")
    a = store.get_advisory("CVE-2024-0001")
    assert a.epss_score == 0.88
    assert a.epss_percentile == 0.98

    # Update KEV status
    store.set_kev_status("CVE-2024-0001", is_kev=True, date_added="2026-11-10")
    a2 = store.get_advisory("CVE-2024-0001")
    assert a2.is_kev is True
    assert a2.kev_date_added == "2026-11-10"

    store.close()


def test_intel_store_staleness():
    store = IntelStore(":memory:")
    # Empty store
    stale_empty = store.get_staleness_info(max_age_days=7)
    assert stale_empty["is_stale"] is True
    assert stale_empty["last_updated"] is None

    # Sync state within 2 days
    now = datetime.now(UTC)
    store.update_sync_state(
        SyncState(source="nvd", last_sync_time=(now - timedelta(days=2)).isoformat(), status="success")
    )
    store.upsert_advisory(AdvisoryRecord(id="CVE-1", source="nvd"))
    stale_fresh = store.get_staleness_info(max_age_days=7)
    assert stale_fresh["is_stale"] is False
    assert stale_fresh["age_days"] == pytest.approx(2.0, abs=0.2)

    # Sync state older than 7 days
    store.update_sync_state(
        SyncState(source="nvd", last_sync_time=(now - timedelta(days=10)).isoformat(), status="success")
    )
    stale_old = store.get_staleness_info(max_age_days=7)
    assert stale_old["is_stale"] is True
    assert stale_old["age_days"] == pytest.approx(10.0, abs=0.2)

    store.close()


# ============================================================================
# 3. Recorded Offline Fixtures for Fetchers
# ============================================================================

@pytest.mark.asyncio
async def test_cisa_kev_fetcher_with_fixture():
    fixture = {
        "title": "CISA Known Exploited Vulnerabilities Catalog",
        "catalogVersion": "2026.11.09",
        "count": 1,
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-44228",
                "vendorProject": "Apache",
                "product": "Log4j",
                "vulnerabilityName": "Apache Log4j Remote Code Execution Vulnerability",
                "dateAdded": "2021-12-10",
                "shortDescription": "Apache Log4j2 contains an RCE vulnerability in JNDI lookup.",
                "requiredAction": "Apply updates per vendor instructions.",
                "dueDate": "2021-12-24",
                "knownRansomwareCampaignUse": "Known",
            }
        ],
    }

    store = IntelStore(":memory:")
    fetcher = CisaKevFetcher()

    mock_resp = mock.MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = fixture
    mock_resp.headers = {"ETag": '"kev-etag-123"', "Last-Modified": "Mon, 09 Nov 2026 00:00:00 GMT"}

    with mock.patch.object(fetcher, "request_with_retry", return_value=mock_resp):
        res = await fetcher.fetch(store)
        assert res.status == "success"
        assert res.records_count == 1
        assert res.etag == '"kev-etag-123"'

    adv = store.get_advisory("CVE-2021-44228")
    assert adv is not None
    assert adv.is_kev is True
    assert adv.kev_date_added == "2021-12-10"
    assert "Log4j" in adv.title

    # Test 304 Not Modified
    mock_304 = mock.MagicMock()
    mock_304.status_code = 304
    mock_304.headers = {}
    store.update_sync_state(SyncState(source="cisa_kev", etag='"kev-etag-123"', records_count=1))

    with mock.patch.object(fetcher, "request_with_retry", return_value=mock_304):
        res304 = await fetcher.fetch(store)
        assert res304.status == "not_modified"
        assert res304.records_count == 1

    store.close()


@pytest.mark.asyncio
async def test_epss_fetcher_with_fixture():
    csv_text = (
        "#model_version:v2023.03.01,score_date:2026-11-09T00:00:00+0000\n"
        "cve,epss,percentile\n"
        "CVE-2021-44228,0.97541,0.99980\n"
        "CVE-2023-1234,0.04500,0.45000\n"
    )
    gz_bytes = gzip.compress(csv_text.encode("utf-8"))

    store = IntelStore(":memory:")
    store.upsert_advisory(AdvisoryRecord(id="CVE-2021-44228", source="nvd"))

    fetcher = EpssFetcher()

    mock_resp = mock.MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = gz_bytes
    mock_resp.headers = {"ETag": '"epss-1"'}

    with mock.patch.object(fetcher, "request_with_retry", return_value=mock_resp):
        res = await fetcher.fetch(store)
        assert res.status == "success"
        assert res.records_count == 2

    adv = store.get_advisory("CVE-2021-44228")
    assert adv.epss_score == pytest.approx(0.97541)
    assert adv.epss_percentile == pytest.approx(0.99980)

    store.close()


@pytest.mark.asyncio
async def test_osv_fetcher_with_fixture():
    osv_json = {
        "id": "GHSA-j876-hfhm-w8cx",
        "summary": "Express.js open redirect vulnerability",
        "details": "A crafted URL allows an attacker to redirect users to untrusted websites.",
        "aliases": ["CVE-2024-99999"],
        "modified": "2026-11-09T10:00:00Z",
        "published": "2026-11-01T10:00:00Z",
        "database_specific": {"severity": "HIGH"},
        "affected": [
            {
                "package": {"name": "express", "ecosystem": "npm"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [{"introduced": "4.0.0"}, {"fixed": "4.19.2"}],
                    }
                ],
                "versions": ["4.18.0", "4.18.1"],
            }
        ],
    }

    # Package into a zip in memory
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("GHSA-j876-hfhm-w8cx.json", json.dumps(osv_json))
    zip_bytes = buf.getvalue()

    store = IntelStore(":memory:")
    fetcher = OsvFetcher(ecosystems=["npm"])

    mock_resp = mock.MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = zip_bytes
    mock_resp.headers = {"ETag": '"osv-npm-1"'}

    with mock.patch.object(fetcher, "request_with_retry", return_value=mock_resp):
        res = await fetcher.fetch(store)
        assert res.status == "success"
        assert res.records_count == 1

    adv = store.get_advisory("GHSA-j876-hfhm-w8cx")
    assert adv is not None
    assert adv.severity == "HIGH"
    assert "CVE-2024-99999" in adv.aliases
    assert len(adv.packages) == 1
    assert adv.packages[0].package_name == "express"
    assert adv.packages[0].fixed == "4.19.2"

    store.close()


@pytest.mark.asyncio
async def test_ghsa_fetcher_with_fixture():
    ghsa_fixture = [
        {
            "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
            "cve_id": "CVE-2024-8888",
            "summary": "Prototype pollution in lodash",
            "description": "lodash versions prior to 4.17.21 are vulnerable to prototype pollution.",
            "severity": "critical",
            "cvss": {"score": 9.8, "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            "published_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-02-01T00:00:00Z",
            "vulnerabilities": [
                {
                    "package": {"ecosystem": "npm", "name": "lodash"},
                    "vulnerable_version_range": "< 4.17.21",
                    "first_patched_version": {"identifier": "4.17.21"},
                }
            ],
        }
    ]

    store = IntelStore(":memory:")
    fetcher = GhsaFetcher()

    mock_resp = mock.MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = ghsa_fixture
    mock_resp.headers = {"ETag": '"ghsa-etag-1"'}

    with mock.patch.object(fetcher, "request_with_retry", return_value=mock_resp):
        res = await fetcher.fetch(store)
        assert res.status == "success"
        assert res.records_count == 1

    adv = store.get_advisory("GHSA-xxxx-yyyy-zzzz")
    assert adv is not None
    assert adv.severity == "CRITICAL"
    assert adv.cvss_score == 9.8
    assert len(adv.packages) == 1
    assert adv.packages[0].fixed == "4.17.21"

    store.close()


@pytest.mark.asyncio
async def test_nvd_fetcher_with_fixture():
    nvd_fixture = {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2023-38545",
                    "descriptions": [{"lang": "en", "value": "SOCKS5 heap buffer overflow in curl"}],
                    "published": "2023-10-11T00:00:00",
                    "lastModified": "2023-10-15T00:00:00",
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                }
                            }
                        ]
                    },
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "criteria": "cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*",
                                            "versionStartIncluding": "7.69.0",
                                            "versionEndExcluding": "8.4.0",
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                }
            }
        ],
    }

    store = IntelStore(":memory:")
    fetcher = NvdFetcher(api_key="mock-key")

    mock_resp = mock.MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = nvd_fixture
    mock_resp.headers = {}

    with mock.patch.object(fetcher, "request_with_retry", return_value=mock_resp):
        res = await fetcher.fetch(store)
        assert res.status == "success"
        assert res.records_count == 1

    adv = store.get_advisory("CVE-2023-38545")
    assert adv is not None
    assert adv.cvss_score == 9.8
    assert adv.severity == "CRITICAL"
    assert len(adv.packages) == 1
    assert adv.packages[0].package_name == "curl"
    assert adv.packages[0].introduced == "7.69.0"
    assert adv.packages[0].fixed == "8.4.0"

    store.close()


@pytest.mark.asyncio
async def test_updater_error_handling_and_summary():
    store = IntelStore(":memory:")
    updater = IntelUpdater(store=store)

    # Simulate 403 Forbidden on CISA
    mock_resp = mock.MagicMock()
    mock_resp.status_code = 403
    mock_resp.headers = {}

    with mock.patch.object(
        updater.fetchers["cisa_kev"],
        "request_with_retry",
        side_effect=httpx.HTTPStatusError("403 Forbidden", request=mock.MagicMock(), response=mock_resp),
    ):
        results = await updater.update(sources=["cisa_kev"])
        assert len(results) == 1
        assert results[0].status == "error"
        assert "403 Forbidden" in results[0].error_message

    # Verify sync_state recorded
    sync = store.get_sync_state("cisa_kev")
    assert "error" in sync.status

    store.close()


# ============================================================================
# 4. Air-Gapped Offline Bundle Export & Import Tests
# ============================================================================

def test_bundle_export_import_and_signature_verification():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        src_db = tmp_path / "src.db"
        dst_db = tmp_path / "dst.db"
        bundle_zip = tmp_path / "intel_bundle.zip"

        s1 = IntelStore(src_db)
        adv = AdvisoryRecord(
            id="CVE-2024-5555",
            source="ghsa",
            title="Remote Execution in request-lib",
            description="Allows remote code execution via unsafe deserialize",
            cvss_score=9.1,
            severity="CRITICAL",
            epss_score=0.92,
            is_kev=True,
            aliases=["GHSA-5555-6666"],
            packages=[PackageRange(ecosystem="pypi", package_name="request-lib", introduced="1.0", fixed="2.0")],
        )
        s1.upsert_advisory(adv)
        s1.update_sync_state(SyncState(source="ghsa", last_sync_time="2026-11-09T00:00:00Z", records_count=1, status="success"))

        # Export bundle
        out_file = export_bundle(bundle_zip, s1)
        assert out_file.exists()
        s1.close()

        # Import into fresh store
        s2 = IntelStore(dst_db)
        res = import_bundle(out_file, s2)
        assert res["status"] == "success"
        assert res["imported_advisories"] == 1

        imported_adv = s2.get_advisory("CVE-2024-5555")
        assert imported_adv is not None
        assert imported_adv.title == "Remote Execution in request-lib"
        assert imported_adv.is_kev is True
        assert imported_adv.epss_score == 0.92
        assert len(imported_adv.packages) == 1
        s2.close()


def test_bundle_rejects_tampered_manifest_and_data():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        src_db = tmp_path / "src.db"
        bundle_zip = tmp_path / "bundle.zip"

        s1 = IntelStore(src_db)
        s1.upsert_advisory(AdvisoryRecord(id="CVE-1", source="test"))
        export_bundle(bundle_zip, s1)
        s1.close()

        # 1. Tamper manifest.json -> fails Ed25519 signature
        tampered_manifest_zip = tmp_path / "tampered_manifest.zip"
        with zipfile.ZipFile(bundle_zip, "r") as zin, zipfile.ZipFile(tampered_manifest_zip, "w") as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                if item.filename == "manifest.json":
                    data = data.replace(b"kelan", b"tampered")
                zout.writestr(item, data)

        s_test1 = IntelStore(tmp_path / "test1.db")
        with pytest.raises(BundleVerificationError, match="Ed25519 signature verification failed"):
            import_bundle(tampered_manifest_zip, s_test1)
        s_test1.close()

        # 2. Tamper intel.db -> fails SHA-256
        tampered_db_zip = tmp_path / "tampered_db.zip"
        with zipfile.ZipFile(bundle_zip, "r") as zin, zipfile.ZipFile(tampered_db_zip, "w") as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                if item.filename == "intel.db":
                    data = data + b"extra_corrupt_bytes"
                zout.writestr(item, data)

        s_test2 = IntelStore(tmp_path / "test2.db")
        with pytest.raises(BundleVerificationError, match="Checksum mismatch for intel.db"):
            import_bundle(tampered_db_zip, s_test2)
        s_test2.close()


# ============================================================================
# 5. Trending & Search Tests
# ============================================================================

def test_trending_and_search_methods():
    store = IntelStore(":memory:")
    # Seed advisories
    adv1 = AdvisoryRecord(
        id="CVE-2024-9001",
        source="cisa_kev",
        title="High Severity KEV Exploit",
        cvss_score=9.6,
        epss_score=0.91,
        is_kev=True,
        kev_date_added="2026-11-09",
        packages=[PackageRange(ecosystem="pypi", package_name="vuln-lib", fixed="2.0.0")],
    )
    store.upsert_advisory(adv1)

    # Seed EPSS history across multiple dates
    d1 = (datetime.now(UTC) - timedelta(days=7)).strftime("%Y-%m-%d")
    d2 = datetime.now(UTC).strftime("%Y-%m-%d")
    store.record_epss_score("CVE-2024-9001", score=0.45, date_str=d1)
    store.record_epss_score("CVE-2024-9001", score=0.91, date_str=d2)

    # Record scanned packages
    store.record_scanned_packages([PackageSpec(name="vuln-lib", version="1.5.0", ecosystem="pypi")])

    # 1. Trending KEV
    kevs = store.get_trending_kev()
    assert len(kevs) == 1
    assert kevs[0]["id"] == "CVE-2024-9001"

    # 2. Trending EPSS 7-day risers
    epss_risers = store.get_trending_epss(days=7)
    assert len(epss_risers) == 1
    assert epss_risers[0]["cve"] == "CVE-2024-9001"
    assert epss_risers[0]["delta"] == pytest.approx(0.46, abs=0.01)

    # 3. Trending scanned
    scanned_advs = store.get_trending_scanned()
    assert len(scanned_advs) == 1
    assert scanned_advs[0]["advisory_id"] == "CVE-2024-9001"
    assert scanned_advs[0]["package_name"] == "vuln-lib"

    # 4. Search
    sr = store.search("vuln-lib")
    assert len(sr) == 1
    assert sr[0].id == "CVE-2024-9001"

    # Test rendering functions do not throw
    show_trending(store)
    show_search(store, "vuln-lib")

    store.close()


# ============================================================================
# 6. SCA Plugin Manifest & Lockfile Parsing Across All Ecosystems
# ============================================================================

@pytest.mark.asyncio
async def test_sca_manifest_parsers_all_ecosystems(tmp_path):
    sca = ScaPlugin()

    # 1. requirements.txt
    (tmp_path / "requirements.txt").write_text("flask==2.3.2\nwerkzeug===2.3.0\n# comment")

    # 2. Pipfile.lock
    (tmp_path / "Pipfile.lock").write_text(json.dumps({
        "default": {"jinja2": {"version": "==3.1.2"}}
    }))

    # 3. poetry.lock
    (tmp_path / "poetry.lock").write_text(
        "[[package]]\nname = 'requests'\nversion = '2.31.0'\n"
    )

    # 4. package.json
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"express": "^4.18.2"},
        "devDependencies": {"mocha": "~10.2.0"},
    }))

    # 5. package-lock.json
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "packages": {
            "node_modules/body-parser": {"version": "1.20.1"}
        }
    }))

    # 6. yarn.lock
    (tmp_path / "yarn.lock").write_text(
        '"cors@^2.8.5":\n  version "2.8.5"\n'
    )

    # 7. pnpm-lock.yaml
    (tmp_path / "pnpm-lock.yaml").write_text(
        "packages:\n  /debug@4.3.4:\n    resolution: {}\n"
    )

    # 8. Cargo.lock
    (tmp_path / "Cargo.lock").write_text(
        "[[package]]\nname = 'tokio'\nversion = '1.35.0'\n"
    )

    # 9. Cargo.toml
    (tmp_path / "Cargo.toml").write_text(
        '[dependencies]\nserde = "1.0.193"\n'
    )

    # 10. go.mod
    (tmp_path / "go.mod").write_text(
        "module test\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n)\n"
    )

    # 11. go.sum
    (tmp_path / "go.sum").write_text(
        "golang.org/x/crypto v0.14.0 h1:abc=\n"
    )

    # 12. pom.xml
    (tmp_path / "pom.xml").write_text(
        "<project><dependencies><dependency>"
        "<groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version>"
        "</dependency></dependencies></project>"
    )

    # 13. build.gradle
    (tmp_path / "build.gradle").write_text(
        "dependencies { implementation 'com.fasterxml.jackson.core:jackson-databind:2.13.0' }\n"
    )

    specs = await sca._collect_manifests(tmp_path)
    ecosystems = {s["eco"] for s in specs}
    names = {s["name"] for s in specs}

    assert "PyPI" in ecosystems
    assert "npm" in ecosystems
    assert "crates.io" in ecosystems
    assert "Go" in ecosystems
    assert "Maven" in ecosystems

    # Verify specific packages parsed
    assert "flask" in names
    assert "jinja2" in names
    assert "requests" in names
    assert "express" in names
    assert "body-parser" in names
    assert "cors" in names
    assert "debug" in names
    assert "tokio" in names
    assert "serde" in names
    assert "github.com/gin-gonic/gin" in names
    assert "golang.org/x/crypto" in names
    assert "log4j-core" in names
    assert "jackson-databind" in names


# ============================================================================
# 7. SCA Plugin Offline Matching, EPSS/KEV Enrichment & Staleness
# ============================================================================

@pytest.mark.asyncio
async def test_sca_local_matching_and_enrichment(tmp_path):
    # Setup test repo with requirements.txt
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("vulnerable-pkg==1.2.0\nsafe-pkg==2.0.0\n")

    # Setup local intel store
    db_file = tmp_path / "intel_test.db"
    store = IntelStore(db_file)
    store.upsert_advisory(
        AdvisoryRecord(
            id="CVE-2024-7777",
            source="nvd",
            title="Critical SQL Injection",
            severity="CRITICAL",
            cvss_score=9.8,
            epss_score=0.965,
            is_kev=True,
            kev_date_added="2026-11-08",
            aliases=["GHSA-7777-8888"],
            packages=[
                PackageRange(ecosystem="pypi", package_name="vulnerable-pkg", introduced="1.0.0", fixed="1.5.0")
            ],
        )
    )
    # Record sync state so it's not stale
    store.update_sync_state(
        SyncState(source="nvd", last_sync_time=datetime.now(UTC).isoformat(), status="success")
    )
    store.close()

    target = ScanTarget(ScopeKind.CODEBASE, str(tmp_path))
    ctx = ScanContext(
        target,
        ScanConfig(values={"intel_db": str(db_file), "allow_network": False}),
        tmp_path,
    )

    sca = ScaPlugin()
    res = await sca.run(ctx)

    # Assert matching vulnerability found
    vuln_findings = [f for f in res.findings if "vulnerable-pkg" in f.title]
    assert len(vuln_findings) == 1

    f = vuln_findings[0]
    assert f.severity == Severity.CRITICAL
    assert "CVE-2024-7777" in f.title
    assert f.location == "requirements.txt:vulnerable-pkg@1.2.0"

    # Check evidence enrichment (EPSS, KEV, CVSS)
    assert len(f.evidence) >= 1
    ev_extra = f.evidence[0].extra
    assert ev_extra.get("is_kev") is True
    assert ev_extra.get("epss_score") == 0.965
    assert ev_extra.get("cvss_score") == 9.8

    # Safe package should not have finding
    assert not any("safe-pkg" in f.title for f in res.findings)

    # Local-first active notice
    assert res.meta.get("network_call") == "disabled"
    assert "Local-first active" in res.meta.get("notice", "")


@pytest.mark.asyncio
async def test_sca_staleness_warning_and_report_timestamp(tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.31.0\n")

    db_file = tmp_path / "intel_stale.db"
    store = IntelStore(db_file)
    # Stale sync timestamp (20 days ago)
    old_time = (datetime.now(UTC) - timedelta(days=20)).isoformat()
    store.update_sync_state(SyncState(source="nvd", last_sync_time=old_time, status="success"))
    store.close()

    target = ScanTarget(ScopeKind.CODEBASE, str(tmp_path))
    ctx = ScanContext(
        target,
        ScanConfig(values={"intel_db": str(db_file), "max_intel_age_days": 7}),
        tmp_path,
    )

    sca = ScaPlugin()
    res = await sca.run(ctx)

    assert res.meta.get("intel_is_stale") is True
    assert res.meta.get("intel_last_updated") == old_time
    assert "staleness_warning" in res.meta

    assert "stale or uninitialized" in res.meta.get("staleness_warning", "")

    # Check report generation includes last update
    fs = FindingSet()
    fs.extend(res.findings)
    html_out = tmp_path / "report.html"
    json_out = tmp_path / "report.json"
    fs.write_html(str(html_out), intel_updated=old_time)
    fs.write_json(str(json_out), intel_updated=old_time)

    assert html_out.exists()
    assert old_time in html_out.read_text()
    assert json_out.exists()
    assert old_time in json_out.read_text()


# ============================================================================
# 8. CLI Command Integration Tests
# ============================================================================

def test_cli_update_export_intel(tmp_path, monkeypatch):
    db_path = tmp_path / "cli_intel.db"
    bundle_zip = tmp_path / "test_bundle.zip"

    # 1. Export empty bundle
    ret = cmd_export_bundle(["--output", str(bundle_zip), "--db", str(db_path)])
    assert ret == 0
    assert bundle_zip.exists()

    # 2. Import bundle with update --offline-bundle
    ret_import = cmd_update(["--offline-bundle", str(bundle_zip), "--db", str(db_path)])
    assert ret_import == 0

    # 3. Trending command
    monkeypatch.setenv("KELAN_INTEL_DB", str(db_path))
    ret_trending = cmd_intel(["trending"])
    assert ret_trending == 0

    # 4. Search command
    ret_search = cmd_intel(["search", "CVE-2021-44228"])
    assert ret_search == 0
