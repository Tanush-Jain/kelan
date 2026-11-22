# ══ Kelan Community: User-Extensible Intelligence Bridge ════════════════════════
# License: MIT License (https://opensource.org/licenses/MIT)
#
# Deliberately limited for Community edition: safe, deterministic, human-in-the-loop.
# Exactly three source types supported:
#   1. rss: RSS/Atom feeds parsed via feedparser with HTML/script tags stripped.
#   2. json-feed: JSON feeds matching declared minimal schema (title, id/cve, severity, published date, url, summary).
#   3. local-doc: Local Markdown/text documents ingested as inert read-only context.
#
# Arbitrary website scraping and autonomous agent actions are strictly Pro-only features.

from __future__ import annotations

import html
import ipaddress
import json
import os
import re
import socket
import time
import tomllib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
import structlog

from kelan.intel.fetchers.base import BaseFetcher, FetchResult
from kelan.intel.models import AdvisoryRecord

log = structlog.get_logger("kelan.intel.sources")


def get_platform_dirs() -> tuple[Path, Path]:
    """Returns standard platform (data_dir, config_dir)."""
    import platform

    system = platform.system().lower()
    home = Path.home()

    if "windows" in system:
        local_app = os.environ.get("LOCALAPPDATA") or str(home / "AppData" / "Local")
        roaming_app = os.environ.get("APPDATA") or str(home / "AppData" / "Roaming")
        data_dir = Path(local_app) / "kelan"
        config_dir = Path(roaming_app) / "kelan"
    elif "darwin" in system:
        data_dir = home / "Library" / "Application Support" / "kelan"
        config_dir = data_dir
    else:  # Linux and POSIX
        data_home = os.environ.get("XDG_DATA_HOME") or str(home / ".local" / "share")
        config_home = os.environ.get("XDG_CONFIG_HOME") or str(home / ".config")
        data_dir = Path(data_home) / "kelan"
        config_dir = Path(config_home) / "kelan"

    return data_dir, config_dir

PRO_UPGRADE_MSG = (
    "kelan: arbitrary website scraping is a Pro feature.\n"
    "Community supports structured feeds (rss, json-feed) and local documents (local-doc).\n"
    "See https://kelansecurity.vercel.app for Pro."
)


def sanitize_text(text: str) -> str:
    """Strips HTML tags, script blocks, and unescapes HTML entities safely."""
    if not text:
        return ""
    clean = re.sub(r"<script.*?</script>", "", text, flags=re.DOTALL | re.IGNORECASE)
    clean = re.sub(r"<style.*?</style>", "", clean, flags=re.DOTALL | re.IGNORECASE)
    clean = re.sub(r"<[^>]+>", " ", clean)
    clean = html.unescape(clean)
    return " ".join(clean.split())


def is_ip_private_or_local(ip_str: str) -> bool:
    """Checks whether an IP address belongs to loopback, private, link-local, or reserved ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip == ipaddress.IPv4Address("0.0.0.0")  # nosec B104
            or ip == ipaddress.IPv4Address("255.255.255.255")
        )
    except ValueError:
        return False


def validate_feed_url(url: str, allow_local: bool = False) -> tuple[bool, str | None]:
    """
    Validates a feed URL against SSRF and unsupported bare-HTML web scraping:
    - Enforces HTTPS by default (HTTP allowed only if allow_local=True).
    - Blocks private, loopback (127.0.0.1, ::1), and cloud metadata (169.254.169.254) IPs unless allow_local=True.
    - Rejects bare HTML pages with a clear Pro upgrade message.
    """
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return False, f"Invalid URL '{url}': missing scheme or host."

    scheme = parsed.scheme.lower()
    if scheme != "https":
        if allow_local and scheme == "http":
            pass
        else:
            return False, (
                f"URL scheme must be HTTPS (got '{parsed.scheme}'). "
                "Plain HTTP is blocked by default. Pass --allow-local for local test endpoints."
            )

    # Detect bare HTML pages
    path_lower = parsed.path.lower()
    if path_lower.endswith((".html", ".htm")):
        return False, PRO_UPGRADE_MSG

    hostname = parsed.hostname
    if not hostname:
        return False, f"Invalid URL '{url}': unable to extract hostname."

    # Check direct IP literals
    if is_ip_private_or_local(hostname):
        if not allow_local:
            return False, (
                f"SSRF Protection: Host '{hostname}' is a private, loopback, or link-local IP. "
                "Local/internal network fetches are blocked by default. Pass --allow-local to override if intentional."
            )

    # Resolve hostname via DNS to prevent DNS rebinding SSRF
    if not allow_local:
        try:
            addr_info = socket.getaddrinfo(hostname, None)
            for item in addr_info:
                sockaddr = item[4]
                ip_resolved = str(sockaddr[0])
                if is_ip_private_or_local(ip_resolved):
                    return False, (
                        f"SSRF Protection: Host '{hostname}' resolves to private/internal IP '{ip_resolved}'. "
                        "Access to internal network destinations is blocked. Pass --allow-local if this is intentional."
                    )
        except socket.gaierror as e:
            return False, f"DNS resolution failed for host '{hostname}': {e}"

    return True, None


@dataclass
class SourceConfig:
    name: str
    type: str  # "rss", "json-feed", "local-doc"
    url: str  # URL or local filesystem path
    schema_hint: str | None = None
    allow_local: bool = False
    added_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type,
            "url": self.url,
            "schema_hint": self.schema_hint,
            "allow_local": self.allow_local,
            "added_at": self.added_at,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, name: str, data: dict[str, Any]) -> SourceConfig:
        return cls(
            name=name,
            type=data.get("type", "rss"),
            url=data.get("url", ""),
            schema_hint=data.get("schema_hint"),
            allow_local=bool(data.get("allow_local", False)),
            added_at=data.get("added_at") or datetime.now(UTC).isoformat(),
            description=data.get("description", ""),
        )


class BaseSourceAdapter:
    """Base class for intelligence source adapters. Extensible by kelan-pro."""

    source_type: str = "base"

    def __init__(self, config: SourceConfig) -> None:
        self.config = config
        self.log = log

    def validate(self) -> tuple[bool, str | None]:
        raise NotImplementedError

    async def fetch(self, timeout: float = 15.0) -> str:
        raise NotImplementedError

    def parse(self, raw_data: str) -> list[AdvisoryRecord]:
        raise NotImplementedError

    async def test(self) -> dict[str, Any]:
        """Dry-run fetch and parse: returns parsed summary without writing anything to disk or DB."""
        val_ok, val_err = self.validate()
        if not val_ok:
            return {
                "name": self.config.name,
                "type": self.config.type,
                "url": self.config.url,
                "status": "error",
                "error": val_err,
                "records_count": 0,
                "sample_items": [],
            }

        try:
            raw = await self.fetch(timeout=10.0)
            records = self.parse(raw)
            sample = [
                {
                    "id": r.id,
                    "title": r.title,
                    "severity": r.severity,
                    "published_at": r.published_at,
                }
                for r in records[:5]
            ]
            return {
                "name": self.config.name,
                "type": self.config.type,
                "url": self.config.url,
                "status": "success",
                "records_count": len(records),
                "sample_items": sample,
            }
        except Exception as e:
            return {
                "name": self.config.name,
                "type": self.config.type,
                "url": self.config.url,
                "status": "error",
                "error": str(e),
                "records_count": 0,
                "sample_items": [],
            }


class RSSAdapter(BaseSourceAdapter):
    """RSS/Atom feed adapter using feedparser with strict HTML/script stripping."""

    source_type: str = "rss"

    def validate(self) -> tuple[bool, str | None]:
        return validate_feed_url(self.config.url, allow_local=self.config.allow_local)

    async def fetch(self, timeout: float = 15.0) -> str:
        headers = {"User-Agent": "Kelan-Community-Intel/0.1.0"}
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(self.config.url, headers=headers)
            resp.raise_for_status()
            return resp.text

    def parse(self, raw_data: str) -> list[AdvisoryRecord]:
        import feedparser

        feed = feedparser.parse(raw_data)
        if feed.bozo and not feed.entries:
            raise ValueError(f"Malformed RSS/Atom feed: {feed.bozo_exception}")

        records: list[AdvisoryRecord] = []
        now_iso = datetime.now(UTC).isoformat()

        for idx, entry in enumerate(feed.entries):
            raw_title = entry.get("title", "")
            title = sanitize_text(raw_title) or f"Advisory #{idx + 1}"

            raw_summary = entry.get("summary", "") or entry.get("description", "")
            summary = sanitize_text(raw_summary)

            link = entry.get("link", "")
            entry_id = entry.get("id") or entry.get("guid") or link or f"{self.config.name}:{hash(title)}"
            published = entry.get("published") or entry.get("updated") or now_iso

            # Infer severity if tags are present, otherwise default to MEDIUM
            severity = "MEDIUM"
            tags = [t.get("term", "").upper() for t in entry.get("tags", []) if isinstance(t, dict)]
            for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                if s in tags or s in title.upper():
                    severity = s
                    break

            records.append(
                AdvisoryRecord(
                    id=str(entry_id).strip(),
                    source=self.config.name,
                    title=title,
                    description=summary,
                    severity=severity,
                    published_at=str(published),
                    raw_payload=json.dumps({"link": link, "source": self.config.name}),
                )
            )

        return records


class JSONFeedAdapter(BaseSourceAdapter):
    """JSON feed adapter enforcing a strict declared minimal schema."""

    source_type: str = "json-feed"

    def validate(self) -> tuple[bool, str | None]:
        return validate_feed_url(self.config.url, allow_local=self.config.allow_local)

    async def fetch(self, timeout: float = 15.0) -> str:
        headers = {"User-Agent": "Kelan-Community-Intel/0.1.0", "Accept": "application/json"}
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(self.config.url, headers=headers)
            resp.raise_for_status()
            return resp.text

    def _load_schema_mapping(self) -> dict[str, str]:
        if not self.config.schema_hint:
            return {}
        hint_path = Path(self.config.schema_hint).expanduser()
        if not hint_path.is_file():
            raise ValueError(f"Schema hint file not found: {hint_path}")
        try:
            return json.loads(hint_path.read_text(encoding="utf-8"))
        except Exception as e:
            raise ValueError(f"Failed to read schema hint JSON from '{hint_path}': {e}")

    def parse(self, raw_data: str) -> list[AdvisoryRecord]:
        try:
            data = json.loads(raw_data)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON payload: {e}")

        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            for key in ("items", "advisories", "vulnerabilities", "entries", "data"):
                if key in data and isinstance(data[key], list):
                    items = data[key]
                    break
            else:
                raise ValueError(
                    "JSON feed must be an array of items or an object containing an 'items' array."
                )
        else:
            raise ValueError("JSON feed root must be an array or object.")

        mapping = self._load_schema_mapping()
        title_key = mapping.get("title", "title")
        id_key = mapping.get("id", "id")
        sev_key = mapping.get("severity", "severity")
        pub_key = mapping.get("published_date", "published_date")
        url_key = mapping.get("url", "url")
        sum_key = mapping.get("summary", "summary")

        records: list[AdvisoryRecord] = []

        for idx, item in enumerate(items):
            if not isinstance(item, dict):
                raise ValueError(f"JSON feed item at index {idx} is not an object.")

            missing_fields: list[str] = []

            # 1. Title
            title_val = item.get(title_key)
            if not title_val or not str(title_val).strip():
                missing_fields.append("title")

            # 2. ID / CVE
            id_val = item.get(id_key)
            if not id_val and id_key == "id":
                id_val = item.get("cve") or item.get("cve_id") or item.get("reference")
            if not id_val or not str(id_val).strip():
                missing_fields.append("id")

            # 3. Severity
            sev_val = item.get(sev_key)
            if not sev_val or not str(sev_val).strip():
                missing_fields.append("severity")

            # 4. Published Date
            pub_val = item.get(pub_key)
            if not pub_val and pub_key == "published_date":
                pub_val = item.get("published") or item.get("published_at") or item.get("date")
            if not pub_val or not str(pub_val).strip():
                missing_fields.append("published_date")

            # 5. URL
            url_val = item.get(url_key)
            if not url_val and url_key == "url":
                url_val = item.get("link")
            if not url_val or not str(url_val).strip():
                missing_fields.append("url")

            # 6. Summary
            sum_val = item.get(sum_key)
            if not sum_val and sum_key == "summary":
                sum_val = item.get("description")
            if not sum_val or not str(sum_val).strip():
                missing_fields.append("summary")

            if missing_fields:
                raise ValueError(
                    f"JSON feed item at index {idx} violates declared schema: missing required field(s) {missing_fields}. "
                    "Community requires declared minimal schema (title, id/CVE ref, severity, published date, url, summary)."
                )

            records.append(
                AdvisoryRecord(
                    id=str(id_val).strip(),
                    source=self.config.name,
                    title=sanitize_text(str(title_val)),
                    description=sanitize_text(str(sum_val)),
                    severity=str(sev_val).upper().strip(),
                    published_at=str(pub_val).strip(),
                    raw_payload=json.dumps(item),
                )
            )

        return records


class LocalDocAdapter(BaseSourceAdapter):
    """Local knowledge document adapter (markdown/text) ingested as read-only reference context."""

    source_type = "local-doc"

    def validate(self) -> tuple[bool, str | None]:
        doc_path = Path(self.config.url).expanduser()
        if not doc_path.exists():
            return False, f"Local knowledge doc does not exist: {doc_path}"
        if not doc_path.is_file():
            return False, f"Local knowledge doc path is not a file: {doc_path}"
        try:
            size = doc_path.stat().st_size
            if size > 2 * 1024 * 1024:
                return False, f"Local knowledge doc exceeds 2MB limit ({size} bytes)."
        except OSError as e:
            return False, f"Cannot inspect local knowledge doc '{doc_path}': {e}"
        return True, None

    async def fetch(self, timeout: float = 15.0) -> str:
        val_ok, val_err = self.validate()
        if not val_ok:
            raise ValueError(val_err)
        doc_path = Path(self.config.url).expanduser()
        return doc_path.read_text(encoding="utf-8", errors="replace")

    def parse(self, raw_data: str) -> list[AdvisoryRecord]:
        doc_path = Path(self.config.url).expanduser()
        mtime_iso = datetime.fromtimestamp(doc_path.stat().st_mtime, tz=UTC).isoformat()
        return [
            AdvisoryRecord(
                id=f"doc:{self.config.name}",
                source=self.config.name,
                title=f"Knowledge Doc: {self.config.name}",
                description=raw_data,
                severity="INFO",
                published_at=mtime_iso,
                raw_payload=raw_data[:2000],
            )
        ]


# ── Extensible Registry Pattern ──────────────────────────────────────────────

ADAPTER_REGISTRY: dict[str, type[BaseSourceAdapter]] = {
    "rss": RSSAdapter,
    "json-feed": JSONFeedAdapter,
    "local-doc": LocalDocAdapter,
}


def register_adapter(source_type: str, adapter_cls: type[BaseSourceAdapter]) -> None:
    """Registers an adapter class in the registry (extensible by kelan-pro)."""
    ADAPTER_REGISTRY[source_type] = adapter_cls


def get_adapter(config: SourceConfig) -> BaseSourceAdapter:
    """Instantiates the appropriate adapter for a SourceConfig."""
    src_type = config.type.lower()
    if src_type in ("html", "web", "website", "scrape"):
        raise ValueError(PRO_UPGRADE_MSG)

    adapter_cls = ADAPTER_REGISTRY.get(src_type)
    if not adapter_cls:
        valid_types = ", ".join(sorted(ADAPTER_REGISTRY.keys()))
        raise ValueError(
            f"Unsupported source type '{config.type}'. "
            f"Community edition supports: {valid_types}."
        )
    return adapter_cls(config)


# ── CustomSourceFetcher (IntelUpdater Integration) ───────────────────────────


class CustomSourceFetcher(BaseFetcher):
    """Wraps a BaseSourceAdapter to conform to BaseFetcher for IntelUpdater."""

    def __init__(self, adapter: BaseSourceAdapter) -> None:
        super().__init__(timeout=15.0)
        self.adapter = adapter
        self.source_name = adapter.config.name

    async def fetch(self, store: Any) -> FetchResult:
        start = time.time()
        try:
            await self._rate_limit()
            raw = await self.adapter.fetch(timeout=self.timeout)
            records = self.adapter.parse(raw)
            for r in records:
                store.upsert_advisory(r)
            duration = time.time() - start

            self.adapter.log.info(
                "custom_source_sync_success",
                source=self.adapter.config.name,
                url=self.adapter.config.url,
                status="success",
                item_count=len(records),
                duration_s=round(duration, 2),
            )
            return FetchResult(
                source=self.adapter.config.name,
                status="success",
                records_count=len(records),
                duration_s=round(duration, 2),
            )
        except Exception as e:
            duration = time.time() - start
            self.adapter.log.error(
                "custom_source_sync_failed",
                source=self.adapter.config.name,
                url=self.adapter.config.url,
                status="error",
                error=str(e),
                duration_s=round(duration, 2),
            )
            return FetchResult(
                source=self.adapter.config.name,
                status="error",
                error_message=str(e),
                duration_s=round(duration, 2),
            )


# ── SourcesManager (Config Persistence) ──────────────────────────────────────


class SourcesManager:
    """Manages custom intelligence sources stored in ~/.config/kelan/sources.toml."""

    def __init__(self, config_path: Path | None = None) -> None:
        if config_path is not None:
            self.config_path = config_path
        else:
            _, config_dir = get_platform_dirs()
            self.config_path = config_dir / "sources.toml"

    def _ensure_dir(self) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)

    def list_sources(self) -> list[SourceConfig]:
        try:
            if not self.config_path.exists():
                return []
            with open(self.config_path, "rb") as f:
                data = tomllib.load(f)
            sources_dict = data.get("sources", {})
            return [
                SourceConfig.from_dict(name, conf)
                for name, conf in sources_dict.items()
                if isinstance(conf, dict)
            ]
        except (OSError, PermissionError):
            return []
        except Exception as e:
            log.warning("failed_to_load_sources_toml", path=str(self.config_path), error=str(e))
            return []

    def get_source(self, name: str) -> SourceConfig | None:
        for s in self.list_sources():
            if s.name == name:
                return s
        return None

    def add_source(self, config: SourceConfig) -> None:
        current = {s.name: s for s in self.list_sources()}
        current[config.name] = config
        self._write_sources(current)

    def remove_source(self, name: str) -> bool:
        current = {s.name: s for s in self.list_sources()}
        if name in current:
            del current[name]
            self._write_sources(current)
            return True
        return False

    def _write_sources(self, sources: dict[str, SourceConfig]) -> None:
        self._ensure_dir()
        lines = [
            "# Kelan Custom Intelligence Sources (Community Edition)",
            "# Managed automatically by 'kelan intel sources'",
            "",
        ]
        for name, src in sorted(sources.items()):
            lines.append(f"[sources.{name}]")
            lines.append(f"type = {json.dumps(src.type)}")
            lines.append(f"url = {json.dumps(src.url)}")
            lines.append(f"allow_local = {'true' if src.allow_local else 'false'}")
            lines.append(f"added_at = {json.dumps(src.added_at)}")
            if src.schema_hint:
                lines.append(f"schema_hint = {json.dumps(src.schema_hint)}")
            if src.description:
                lines.append(f"description = {json.dumps(src.description)}")
            lines.append("")

        tmp_path = self.config_path.with_suffix(".tmp")
        tmp_path.write_text("\n".join(lines), encoding="utf-8")
        tmp_path.replace(self.config_path)
