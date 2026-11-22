# ══ Unit Tests: Kelan Community Intelligence Sources Bridge ═════════════════════
# License: MIT License (https://opensource.org/licenses/MIT)

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from kelan.intel.db import IntelStore
from kelan.intel.sources import (
    JSONFeedAdapter,
    LocalDocAdapter,
    PRO_UPGRADE_MSG,
    RSSAdapter,
    SourceConfig,
    SourcesManager,
    get_adapter,
    validate_feed_url,
)
from kelan.intel.updater import IntelUpdater


def test_malformed_rss_feed_handled():
    """Verify malformed RSS/Atom feed raises ValueError and does not execute scripts."""
    config = SourceConfig(
        name="bad_rss",
        type="rss",
        url="https://example.com/malformed.xml",
    )
    adapter = RSSAdapter(config)

    malformed_xml = "<rss><channel><item><title>Broken<unclosed>"
    # feedparser might parse what it can or flag bozo
    try:
        records = adapter.parse(malformed_xml)
        # If it recovers, ensure any content is sanitized
        for r in records:
            assert "<script>" not in r.description
    except ValueError as e:
        assert "Malformed" in str(e) or "feed" in str(e).lower()

    # Complete garbage input
    with pytest.raises(ValueError, match="Malformed RSS/Atom feed"):
        adapter.parse("this is not xml at all, just binary/text garbage !!!@@@###")


def test_rss_feed_script_sanitization():
    """Verify RSS entries strip out scripts and HTML tags."""
    config = SourceConfig(
        name="xss_feed",
        type="rss",
        url="https://example.com/feed.xml",
    )
    adapter = RSSAdapter(config)

    rss_payload = """<?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0">
      <channel>
        <title>Advisory Channel</title>
        <item>
          <title><![CDATA[CVE-2024-1234: <script>alert('xss')</script>Critical Bug]]></title>
          <description><![CDATA[<p>A flaw exists in the component. <script src="http://evil.com/payload.js"></script></p>]]></description>
          <link>https://example.com/advisories/cve-2024-1234</link>
          <guid>CVE-2024-1234</guid>
          <category>CRITICAL</category>
        </item>
      </channel>
    </rss>"""

    records = adapter.parse(rss_payload)
    assert len(records) == 1
    rec = records[0]
    assert "<script>" not in rec.title
    assert "<script" not in rec.description
    assert "alert('xss')" not in rec.title
    assert "payload.js" not in rec.description
    assert "CVE-2024-1234" in rec.id
    assert rec.severity == "CRITICAL"


def test_json_feed_missing_required_schema_fields():
    """Verify JSON feed missing required schema fields is rejected, not guessed."""
    config = SourceConfig(
        name="strict_json",
        type="json-feed",
        url="https://example.com/advisories.json",
    )
    adapter = JSONFeedAdapter(config)

    # Missing severity and summary
    invalid_payload = json.dumps([
        {
            "id": "CVE-2024-0001",
            "title": "Buffer Overflow in Parser",
            "published_date": "2024-10-01T00:00:00Z",
            "url": "https://example.com/cve-2024-0001",
            # Missing "severity" and "summary"
        }
    ])

    with pytest.raises(ValueError) as excinfo:
        adapter.parse(invalid_payload)

    err_msg = str(excinfo.value)
    assert "violates declared schema" in err_msg
    assert "severity" in err_msg or "summary" in err_msg

    # Missing id
    invalid_no_id = json.dumps([
        {
            "title": "Advisory without ID",
            "severity": "HIGH",
            "published_date": "2024-10-01",
            "url": "https://example.com/a",
            "summary": "Some summary description.",
        }
    ])
    with pytest.raises(ValueError, match="violates declared schema.*missing required field"):
        adapter.parse(invalid_no_id)


def test_json_feed_valid_schema():
    """Verify valid JSON feed with declared schema parses cleanly into AdvisoryRecords."""
    config = SourceConfig(
        name="good_json",
        type="json-feed",
        url="https://example.com/feed.json",
    )
    adapter = JSONFeedAdapter(config)

    valid_payload = json.dumps({
        "items": [
            {
                "id": "CVE-2024-8888",
                "title": "SQL Injection in Auth Handler",
                "severity": "CRITICAL",
                "published_date": "2024-11-20T12:00:00Z",
                "url": "https://example.com/cve-2024-8888",
                "summary": "An unauthenticated user can bypass authentication via SQL injection.",
            }
        ]
    })

    records = adapter.parse(valid_payload)
    assert len(records) == 1
    assert records[0].id == "CVE-2024-8888"
    assert records[0].severity == "CRITICAL"
    assert records[0].source == "good_json"
    assert "SQL Injection" in records[0].title


def test_ssrf_private_ip_rejected_by_default():
    """Verify private/loopback IP addresses are rejected by default for SSRF prevention."""
    test_urls = [
        "https://127.0.0.1/feed.json",
        "https://127.0.0.2:8443/feed.xml",
        "https://10.0.0.5/advisories",
        "https://192.168.1.100/feed",
        "https://169.254.169.254/latest/meta-data/",
        "https://localhost:8080/feed.json",
    ]

    for u in test_urls:
        ok, err = validate_feed_url(u, allow_local=False)
        assert not ok, f"Expected '{u}' to be blocked by SSRF validation"
        assert "SSRF Protection" in err or "private" in err or "loopback" in err or "blocked" in err


def test_ssrf_private_ip_allowed_with_flag():
    """Verify local/loopback IPs are accepted when allow_local=True."""
    ok, err = validate_feed_url("http://127.0.0.1:8000/feed.json", allow_local=True)
    assert ok, f"Expected local URL to be accepted with allow_local=True, got: {err}"
    assert err is None


def test_bare_html_rejected_as_pro_feature():
    """Verify bare HTML page URLs or HTML type trigger Pro feature guidance."""
    ok, err = validate_feed_url("https://example.com/security/bulletins.html")
    assert not ok
    assert err == PRO_UPGRADE_MSG

    # Test get_adapter rejection for html type
    config = SourceConfig(name="web_page", type="html", url="https://example.com/blog")
    with pytest.raises(ValueError) as exc:
        get_adapter(config)
    assert "arbitrary website scraping is a Pro feature" in str(exc.value)


def test_local_doc_adapter(tmp_path: Path):
    """Verify local Markdown/text documents are ingested as read-only inert reference context."""
    doc_file = tmp_path / "internal_threat_intel.md"
    doc_content = "# Internal Threat Intel\n\nAttacker group APT-99 is targeting port 8080."
    doc_file.write_text(doc_content, encoding="utf-8")

    config = SourceConfig(
        name="internal_intel",
        type="local-doc",
        url=str(doc_file),
    )
    adapter = LocalDocAdapter(config)
    val_ok, val_err = adapter.validate()
    assert val_ok, f"Validation failed: {val_err}"

    content = asyncio.run(adapter.fetch())
    records = adapter.parse(content)
    assert len(records) == 1
    rec = records[0]
    assert rec.id == "doc:internal_intel"
    assert rec.source == "internal_intel"
    assert rec.severity == "INFO"
    assert "APT-99" in rec.description


def test_e2e_add_test_update_flow(tmp_path: Path):
    """End-to-end integration: add source -> test dry-run -> update -> verify in IntelStore."""
    sources_file = tmp_path / "sources.toml"
    mgr = SourcesManager(config_path=sources_file)

    # 1. Prepare local test doc
    doc = tmp_path / "custom_advisories.md"
    doc.write_text("Custom advisory note on zero-day vulnerabilities in libfoo.", encoding="utf-8")

    # 2. Add source
    src_cfg = SourceConfig(
        name="custom_notes",
        type="local-doc",
        url=str(doc),
        description="Local security advisories",
    )
    mgr.add_source(src_cfg)

    # Confirm persistence in sources.toml
    loaded = mgr.list_sources()
    assert len(loaded) == 1
    assert loaded[0].name == "custom_notes"
    assert loaded[0].type == "local-doc"

    # 3. Dry-run test (writes nothing to database)
    adapter = get_adapter(src_cfg)
    test_res = asyncio.run(adapter.test())
    assert test_res["status"] == "success"
    assert test_res["records_count"] == 1
    assert len(test_res["sample_items"]) == 1

    # 4. Run update into an isolated SQLite IntelStore
    db_path = tmp_path / "test_intel.db"
    store = IntelStore(db_path)

    # Before update, store does not have this record
    assert store.get_advisory("doc:custom_notes") is None

    updater = IntelUpdater(store=store, sources_mgr=mgr)
    # Run update only for our custom source
    results = asyncio.run(updater.update(sources=["custom_notes"]))
    assert len(results) == 1
    assert results[0].status == "success"
    assert results[0].records_count == 1

    # 5. Confirm items land in local SQLite store and sync_state
    adv = store.get_advisory("doc:custom_notes")
    assert adv is not None
    assert adv.source == "custom_notes"
    assert "libfoo" in adv.description

    sync = store.get_sync_state("custom_notes")
    assert sync is not None
    assert sync.status == "success"
    assert sync.records_count == 1

    store.close()
