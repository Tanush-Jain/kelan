from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class PackageSpec:
    name: str
    version: str
    ecosystem: str
    source: str = ""

    def key(self) -> str:
        return f"{self.ecosystem.lower()}:{self.name.lower()}@{self.version}"


@dataclass
class PackageRange:
    ecosystem: str
    package_name: str
    introduced: str = "0"
    fixed: str | None = None
    versions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ecosystem": self.ecosystem,
            "package_name": self.package_name,
            "introduced": self.introduced,
            "fixed": self.fixed,
            "versions": self.versions,
        }


@dataclass
class AdvisoryRecord:
    id: str  # Primary advisory ID (e.g. CVE-2023-1234, GHSA-xxxx-xxxx-xxxx)
    source: str  # nvd, cisa_kev, epss, osv, ghsa
    title: str = ""
    description: str = ""
    cvss_score: float | None = None
    cvss_vector: str | None = None
    severity: str = "MEDIUM"  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    epss_score: float | None = None
    epss_percentile: float | None = None
    epss_date: str | None = None
    is_kev: bool = False
    kev_date_added: str | None = None
    published_at: str | None = None
    modified_at: str | None = None
    fetched_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    aliases: list[str] = field(default_factory=list)
    packages: list[PackageRange] = field(default_factory=list)
    raw_payload: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "title": self.title,
            "description": self.description,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "severity": self.severity,
            "epss_score": self.epss_score,
            "epss_percentile": self.epss_percentile,
            "epss_date": self.epss_date,
            "is_kev": self.is_kev,
            "kev_date_added": self.kev_date_added,
            "published_at": self.published_at,
            "modified_at": self.modified_at,
            "fetched_at": self.fetched_at,
            "aliases": self.aliases,
            "packages": [p.to_dict() for p in self.packages],
        }


@dataclass
class SyncState:
    source: str
    etag: str | None = None
    last_modified: str | None = None
    last_sync_time: str | None = None
    records_count: int = 0
    status: str = "idle"

