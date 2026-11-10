from __future__ import annotations

import json
import os
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Self

from kelan.intel.models import AdvisoryRecord, PackageRange, PackageSpec, SyncState
from kelan.intel.version_match import is_version_vulnerable


def get_default_db_path() -> Path:
    raw = os.getenv("KELAN_INTEL_DB")
    if raw:
        p = Path(raw).expanduser().resolve()
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            return p
        except OSError:
            pass

    home_p = Path("~/.kelan/intel.db").expanduser().resolve()
    try:
        home_p.parent.mkdir(parents=True, exist_ok=True)
        return home_p
    except OSError:
        pass

    local_p = Path("./data/intel.db").resolve()
    try:
        local_p.parent.mkdir(parents=True, exist_ok=True)
        return local_p
    except OSError:
        pass

    import tempfile
    return Path(tempfile.gettempdir()) / "kelan_intel.db"


class IntelStore:
    def __init__(self, db_path: str | Path | None = None) -> None:
        if db_path is None:
            self.db_path = get_default_db_path()
        elif str(db_path) == ":memory:":
            self.db_path = Path(":memory:")
        else:
            self.db_path = Path(db_path).expanduser().resolve()
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._conn = sqlite3.connect(
            str(self.db_path),
            timeout=30.0,
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        if str(self.db_path) != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._init_schema()

    def close(self) -> None:
        if self._conn:
            self._conn.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        self.close()

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS advisories (
                    id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    title TEXT,
                    description TEXT,
                    cvss_score REAL,
                    cvss_vector TEXT,
                    severity TEXT DEFAULT 'MEDIUM',
                    epss_score REAL,
                    epss_percentile REAL,
                    epss_date TEXT,
                    is_kev INTEGER DEFAULT 0,
                    kev_date_added TEXT,
                    published_at TEXT,
                    modified_at TEXT,
                    fetched_at TEXT,
                    raw_payload TEXT
                );

                CREATE TABLE IF NOT EXISTS packages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    advisory_id TEXT NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
                    ecosystem TEXT NOT NULL,
                    package_name TEXT NOT NULL,
                    introduced TEXT DEFAULT '0',
                    fixed TEXT,
                    versions_json TEXT
                );

                CREATE TABLE IF NOT EXISTS aliases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    advisory_id TEXT NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
                    alias TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS epss_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve TEXT NOT NULL,
                    epss_score REAL NOT NULL,
                    recorded_date TEXT NOT NULL,
                    UNIQUE(cve, recorded_date)
                );

                CREATE TABLE IF NOT EXISTS sync_state (
                    source TEXT PRIMARY KEY,
                    etag TEXT,
                    last_modified TEXT,
                    last_sync_time TEXT,
                    records_count INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'idle'
                );

                CREATE TABLE IF NOT EXISTS last_scanned_packages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ecosystem TEXT NOT NULL,
                    package_name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    scanned_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_packages_eco_name ON packages(ecosystem, package_name);
                CREATE INDEX IF NOT EXISTS idx_packages_advisory ON packages(advisory_id);
                CREATE INDEX IF NOT EXISTS idx_aliases_alias ON aliases(alias);
                CREATE INDEX IF NOT EXISTS idx_aliases_advisory ON aliases(advisory_id);
                CREATE INDEX IF NOT EXISTS idx_advisories_kev ON advisories(is_kev, kev_date_added);
                CREATE INDEX IF NOT EXISTS idx_epss_history_cve_date ON epss_history(cve, recorded_date);
                CREATE INDEX IF NOT EXISTS idx_scanned_packages ON last_scanned_packages(ecosystem, package_name);
                """
            )

            # Initialize FTS5 table if not exists
            cur = self._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='advisories_fts';"
            )
            if not cur.fetchone():
                self._conn.execute(
                    """
                    CREATE VIRTUAL TABLE advisories_fts USING fts5(
                        advisory_id UNINDEXED,
                        title,
                        description,
                        aliases,
                        package_names,
                        tokenize='porter unicode61'
                    );
                    """
                )

    def upsert_advisory(self, adv: AdvisoryRecord) -> None:
        now = datetime.now(UTC).isoformat()
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO advisories (
                    id, source, title, description, cvss_score, cvss_vector,
                    severity, epss_score, epss_percentile, epss_date, is_kev,
                    kev_date_added, published_at, modified_at, fetched_at, raw_payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    source=coalesce(excluded.source, advisories.source),
                    title=coalesce(nullif(excluded.title, ''), advisories.title),
                    description=coalesce(nullif(excluded.description, ''), advisories.description),
                    cvss_score=coalesce(excluded.cvss_score, advisories.cvss_score),
                    cvss_vector=coalesce(excluded.cvss_vector, advisories.cvss_vector),
                    severity=coalesce(excluded.severity, advisories.severity),
                    epss_score=coalesce(excluded.epss_score, advisories.epss_score),
                    epss_percentile=coalesce(excluded.epss_percentile, advisories.epss_percentile),
                    epss_date=coalesce(excluded.epss_date, advisories.epss_date),
                    is_kev=case when excluded.is_kev = 1 then 1 else advisories.is_kev end,
                    kev_date_added=coalesce(excluded.kev_date_added, advisories.kev_date_added),
                    published_at=coalesce(excluded.published_at, advisories.published_at),
                    modified_at=coalesce(excluded.modified_at, advisories.modified_at),
                    fetched_at=excluded.fetched_at,
                    raw_payload=coalesce(nullif(excluded.raw_payload, ''), advisories.raw_payload)
                """,
                (
                    adv.id,
                    adv.source,
                    adv.title,
                    adv.description,
                    adv.cvss_score,
                    adv.cvss_vector,
                    adv.severity,
                    adv.epss_score,
                    adv.epss_percentile,
                    adv.epss_date,
                    1 if adv.is_kev else 0,
                    adv.kev_date_added,
                    adv.published_at,
                    adv.modified_at,
                    adv.fetched_at or now,
                    adv.raw_payload,
                ),
            )

            # Insert aliases
            existing_aliases = {
                r["alias"]
                for r in self._conn.execute(
                    "SELECT alias FROM aliases WHERE advisory_id = ?", (adv.id,)
                ).fetchall()
            }
            for alias in adv.aliases:
                if alias and alias not in existing_aliases:
                    self._conn.execute(
                        "INSERT INTO aliases (advisory_id, alias) VALUES (?, ?)",
                        (adv.id, alias),
                    )
                    existing_aliases.add(alias)

            # Packages
            if adv.packages:
                # Replace package ranges for this advisory
                self._conn.execute(
                    "DELETE FROM packages WHERE advisory_id = ?", (adv.id,)
                )
                for p in adv.packages:
                    self._conn.execute(
                        """
                        INSERT INTO packages (advisory_id, ecosystem, package_name, introduced, fixed, versions_json)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            adv.id,
                            p.ecosystem.strip().lower(),
                            p.package_name.strip().lower(),
                            p.introduced or "0",
                            p.fixed,
                            json.dumps(p.versions) if p.versions else None,
                        ),
                    )

            # EPSS history recording
            if adv.epss_score is not None:
                rec_date = adv.epss_date or datetime.now(UTC).strftime("%Y-%m-%d")
                self._conn.execute(
                    """
                    INSERT INTO epss_history (cve, epss_score, recorded_date)
                    VALUES (?, ?, ?)
                    ON CONFLICT(cve, recorded_date) DO UPDATE SET epss_score=excluded.epss_score
                    """,
                    (adv.id, adv.epss_score, rec_date),
                )
                for alias in adv.aliases:
                    if alias.upper().startswith("CVE-"):
                        self._conn.execute(
                            """
                            INSERT INTO epss_history (cve, epss_score, recorded_date)
                            VALUES (?, ?, ?)
                            ON CONFLICT(cve, recorded_date) DO UPDATE SET epss_score=excluded.epss_score
                            """,
                            (alias, adv.epss_score, rec_date),
                        )

            # Update FTS index
            self._update_fts_record(adv.id)

    def _update_fts_record(self, advisory_id: str) -> None:
        adv = self._conn.execute(
            "SELECT title, description FROM advisories WHERE id = ?", (advisory_id,)
        ).fetchone()
        if not adv:
            return

        aliases = [
            r["alias"]
            for r in self._conn.execute(
                "SELECT alias FROM aliases WHERE advisory_id = ?", (advisory_id,)
            ).fetchall()
        ]
        pkgs = [
            r["package_name"]
            for r in self._conn.execute(
                "SELECT DISTINCT package_name FROM packages WHERE advisory_id = ?",
                (advisory_id,),
            ).fetchall()
        ]

        self._conn.execute(
            "DELETE FROM advisories_fts WHERE advisory_id = ?", (advisory_id,)
        )
        self._conn.execute(
            """
            INSERT INTO advisories_fts (advisory_id, title, description, aliases, package_names)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                advisory_id,
                adv["title"] or "",
                adv["description"] or "",
                " ".join(aliases),
                " ".join(pkgs),
            ),
        )

    def record_epss_score(
        self,
        cve: str,
        score: float,
        percentile: float | None = None,
        date_str: str | None = None,
    ) -> bool:
        rec_date = date_str or datetime.now(UTC).strftime("%Y-%m-%d")
        updated = False
        with self._conn:
            # Insert into history
            self._conn.execute(
                """
                INSERT INTO epss_history (cve, epss_score, recorded_date)
                VALUES (?, ?, ?)
                ON CONFLICT(cve, recorded_date) DO UPDATE SET epss_score=excluded.epss_score
                """,
                (cve, score, rec_date),
            )

            # Update advisory directly if id matches
            res1 = self._conn.execute(
                """
                UPDATE advisories
                SET epss_score = ?, epss_percentile = ?, epss_date = ?
                WHERE id = ?
                """,
                (score, percentile, rec_date, cve),
            )
            if res1.rowcount > 0:
                updated = True

            # Update advisory if matched via alias
            res2 = self._conn.execute(
                """
                UPDATE advisories
                SET epss_score = ?, epss_percentile = ?, epss_date = ?
                WHERE id IN (SELECT advisory_id FROM aliases WHERE alias = ?)
                """,
                (score, percentile, rec_date, cve),
            )
            if res2.rowcount > 0:
                updated = True

        return updated

    def set_kev_status(
        self,
        cve: str,
        is_kev: bool = True,
        date_added: str | None = None,
        title: str | None = None,
        description: str | None = None,
        raw_payload: str = "",
    ) -> bool:
        date_added = date_added or datetime.now(UTC).strftime("%Y-%m-%d")
        now = datetime.now(UTC).isoformat()
        with self._conn:
            row = self._conn.execute(
                "SELECT id FROM advisories WHERE id = ?", (cve,)
            ).fetchone()
            if row:
                self._conn.execute(
                    """
                    UPDATE advisories
                    SET is_kev = ?, kev_date_added = ?, modified_at = ?
                    WHERE id = ?
                    """,
                    (1 if is_kev else 0, date_added, now, cve),
                )
            else:
                self._conn.execute(
                    """
                    INSERT INTO advisories (
                        id, source, title, description, is_kev, kev_date_added,
                        published_at, modified_at, fetched_at, raw_payload
                    ) VALUES (?, 'cisa_kev', ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        cve,
                        title or f"CISA KEV: {cve}",
                        description or "",
                        1 if is_kev else 0,
                        date_added,
                        date_added,
                        now,
                        now,
                        raw_payload,
                    ),
                )
            self._update_fts_record(cve)
        return True

    def get_advisory(self, advisory_id: str) -> AdvisoryRecord | None:
        cur = self._conn.execute(
            "SELECT * FROM advisories WHERE id = ?", (advisory_id,)
        )
        row = cur.fetchone()
        if not row:
            # Check by alias
            alias_cur = self._conn.execute(
                "SELECT advisory_id FROM aliases WHERE alias = ? LIMIT 1",
                (advisory_id,),
            )
            alias_row = alias_cur.fetchone()
            if not alias_row:
                return None
            row = self._conn.execute(
                "SELECT * FROM advisories WHERE id = ?", (alias_row["advisory_id"],)
            ).fetchone()
            if not row:
                return None

        return self._row_to_advisory(row)

    def _row_to_advisory(
        self, row: sqlite3.Row, conn: sqlite3.Connection | None = None
    ) -> AdvisoryRecord:
        c = conn or self._conn
        aid = row["id"]
        aliases = [
            r["alias"]
            for r in c.execute(
                "SELECT alias FROM aliases WHERE advisory_id = ?", (aid,)
            ).fetchall()
        ]
        pkg_rows = c.execute(
            "SELECT ecosystem, package_name, introduced, fixed, versions_json FROM packages WHERE advisory_id = ?",
            (aid,),
        ).fetchall()
        packages = []
        for pr in pkg_rows:
            v_list = json.loads(pr["versions_json"]) if pr["versions_json"] else []
            packages.append(
                PackageRange(
                    ecosystem=pr["ecosystem"],
                    package_name=pr["package_name"],
                    introduced=pr["introduced"] or "0",
                    fixed=pr["fixed"],
                    versions=v_list,
                )
            )

        return AdvisoryRecord(
            id=row["id"],
            source=row["source"],
            title=row["title"] or "",
            description=row["description"] or "",
            cvss_score=row["cvss_score"],
            cvss_vector=row["cvss_vector"],
            severity=row["severity"] or "MEDIUM",
            epss_score=row["epss_score"],
            epss_percentile=row["epss_percentile"],
            epss_date=row["epss_date"],
            is_kev=bool(row["is_kev"]),
            kev_date_added=row["kev_date_added"],
            published_at=row["published_at"],
            modified_at=row["modified_at"],
            fetched_at=row["fetched_at"] or "",
            aliases=aliases,
            packages=packages,
            raw_payload=row["raw_payload"] or "",
        )

    def search(self, query: str, limit: int = 20) -> list[AdvisoryRecord]:
        q = query.strip()
        if not q:
            return []

        # 1. Direct ID or Alias match
        direct = self.get_advisory(q)
        results: list[AdvisoryRecord] = [direct] if direct else []
        seen_ids = {direct.id} if direct else set()

        # 2. Package name match
        pkg_cur = self._conn.execute(
            """
            SELECT DISTINCT advisory_id FROM packages
            WHERE package_name = ? COLLATE NOCASE
            LIMIT ?
            """,
            (q.lower(), limit),
        )
        for row in pkg_cur.fetchall():
            aid = row["advisory_id"]
            if aid not in seen_ids:
                adv = self.get_advisory(aid)
                if adv:
                    results.append(adv)
                    seen_ids.add(aid)
            if len(results) >= limit:
                return results

        # 3. FTS5 Search
        # Escape FTS special chars
        clean_fts = "".join(c if c.isalnum() or c in ("-", "_") else " " for c in q).strip()
        if clean_fts:
            fts_query = f'"{clean_fts}"'
            try:
                fts_cur = self._conn.execute(
                    """
                    SELECT advisory_id FROM advisories_fts
                    WHERE advisories_fts MATCH ?
                    ORDER BY rank
                    LIMIT ?
                    """,
                    (fts_query, limit),
                )
                for row in fts_cur.fetchall():
                    aid = row["advisory_id"]
                    if aid not in seen_ids:
                        adv = self.get_advisory(aid)
                        if adv:
                            results.append(adv)
                            seen_ids.add(aid)
                    if len(results) >= limit:
                        break
            except sqlite3.OperationalError:
                pass

        return results

    def match_packages(
        self, specs: list[PackageSpec]
    ) -> list[tuple[PackageSpec, AdvisoryRecord]]:
        """Match package specifications against vulnerability database using version ranges."""
        matches: list[tuple[PackageSpec, AdvisoryRecord]] = []
        if not specs:
            return matches

        for spec in specs:
            eco = spec.ecosystem.strip().lower()
            name = spec.name.strip().lower()
            version = spec.version.strip()

            cur = self._conn.execute(
                """
                SELECT p.advisory_id, p.introduced, p.fixed, p.versions_json
                FROM packages p
                WHERE (p.ecosystem = ? OR p.ecosystem = 'all')
                  AND p.package_name = ?
                """,
                (eco, name),
            )
            rows = cur.fetchall()
            for r in rows:
                v_list = json.loads(r["versions_json"]) if r["versions_json"] else []
                if is_version_vulnerable(
                    version=version,
                    introduced=r["introduced"] or "0",
                    fixed=r["fixed"],
                    specific_versions=v_list,
                ):
                    adv = self.get_advisory(r["advisory_id"])
                    if adv:
                        matches.append((spec, adv))

        return matches

    def record_scanned_packages(self, specs: list[PackageSpec]) -> None:
        now = datetime.now(UTC).isoformat()
        with self._conn:
            for s in specs:
                self._conn.execute(
                    """
                    INSERT INTO last_scanned_packages (ecosystem, package_name, version, scanned_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (s.ecosystem.lower(), s.name.lower(), s.version, now),
                )

    def get_trending_kev(self, limit: int = 10) -> list[dict[str, Any]]:
        cur = self._conn.execute(
            """
            SELECT id, title, kev_date_added, cvss_score, epss_score
            FROM advisories
            WHERE is_kev = 1
            ORDER BY coalesce(kev_date_added, published_at) DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [dict(r) for r in cur.fetchall()]

    def get_trending_epss(self, limit: int = 10, days: int = 7) -> list[dict[str, Any]]:
        """Find CVEs with the highest EPSS score increase over the last `days` days."""
        # Query distinct recorded dates in epss_history
        dates = [
            r["recorded_date"]
            for r in self._conn.execute(
                "SELECT DISTINCT recorded_date FROM epss_history ORDER BY recorded_date DESC"
            ).fetchall()
        ]
        if len(dates) < 2:
            # Fallback to top current EPSS scores if history has fewer than 2 dates
            cur = self._conn.execute(
                """
                SELECT id as cve, epss_score as current_score, 0.0 as delta, epss_score as previous_score
                FROM advisories
                WHERE epss_score IS NOT NULL
                ORDER BY epss_score DESC
                LIMIT ?
                """,
                (limit,),
            )
            return [dict(r) for r in cur.fetchall()]

        latest_date = dates[0]
        # Find closest date >= days ago
        prior_date = dates[-1]
        for d in dates:
            if d <= (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%d"):
                prior_date = d
                break

        cur = self._conn.execute(
            """
            SELECT
                h1.cve,
                h1.epss_score as current_score,
                h2.epss_score as previous_score,
                (h1.epss_score - h2.epss_score) as delta
            FROM epss_history h1
            JOIN epss_history h2 ON h1.cve = h2.cve
            WHERE h1.recorded_date = ? AND h2.recorded_date = ? AND (h1.epss_score - h2.epss_score) > 0
            ORDER BY delta DESC
            LIMIT ?
            """,
            (latest_date, prior_date, limit),
        )
        rows = [dict(r) for r in cur.fetchall()]
        if not rows:
            # If no delta > 0, return top current EPSS scores
            cur = self._conn.execute(
                """
                SELECT id as cve, epss_score as current_score, 0.0 as delta, epss_score as previous_score
                FROM advisories
                WHERE epss_score IS NOT NULL
                ORDER BY epss_score DESC
                LIMIT ?
                """,
                (limit,),
            )
            return [dict(r) for r in cur.fetchall()]
        return rows

    def get_trending_scanned(self, limit: int = 10) -> list[dict[str, Any]]:
        """Advisories matching packages found in recent user scans."""
        cur = self._conn.execute(
            """
            SELECT DISTINCT
                s.ecosystem,
                s.package_name,
                s.version,
                a.id as advisory_id,
                a.title,
                a.severity,
                a.cvss_score,
                a.epss_score,
                a.is_kev
            FROM last_scanned_packages s
            JOIN packages p ON s.ecosystem = p.ecosystem AND s.package_name = p.package_name
            JOIN advisories a ON p.advisory_id = a.id
            ORDER BY s.scanned_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [dict(r) for r in cur.fetchall()]

    def get_sync_state(self, source: str) -> SyncState:
        cur = self._conn.execute(
            "SELECT * FROM sync_state WHERE source = ?", (source,)
        )
        row = cur.fetchone()
        if not row:
            return SyncState(source=source)
        return SyncState(
            source=row["source"],
            etag=row["etag"],
            last_modified=row["last_modified"],
            last_sync_time=row["last_sync_time"],
            records_count=row["records_count"] or 0,
            status=row["status"] or "idle",
        )

    def update_sync_state(self, state: SyncState) -> None:
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO sync_state (source, etag, last_modified, last_sync_time, records_count, status)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(source) DO UPDATE SET
                    etag=excluded.etag,
                    last_modified=excluded.last_modified,
                    last_sync_time=excluded.last_sync_time,
                    records_count=excluded.records_count,
                    status=excluded.status
                """,
                (
                    state.source,
                    state.etag,
                    state.last_modified,
                    state.last_sync_time,
                    state.records_count,
                    state.status,
                ),
            )

    def get_staleness_info(self, max_age_days: int = 7) -> dict[str, Any]:
        cur = self._conn.execute(
            "SELECT max(last_sync_time) as latest_sync, count(*) as count FROM sync_state WHERE status != 'error'"
        )
        row = cur.fetchone()
        latest = row["latest_sync"] if row else None
        adv_count = self._conn.execute("SELECT count(*) as c FROM advisories").fetchone()["c"]

        if not latest:
            return {
                "last_updated": None,
                "age_days": None,
                "is_stale": True,
                "max_age_days": max_age_days,
                "has_data": False,
                "advisories_count": 0,
            }

        try:
            dt = datetime.fromisoformat(latest)
            age = (datetime.now(UTC) - dt).total_seconds() / 86400.0
            is_stale = (age > max_age_days) or (adv_count == 0)
            return {
                "last_updated": latest,
                "age_days": round(age, 1),
                "is_stale": is_stale,
                "max_age_days": max_age_days,
                "has_data": adv_count > 0,
                "advisories_count": adv_count,
            }
        except Exception:
            return {
                "last_updated": latest,
                "age_days": None,
                "is_stale": True,
                "max_age_days": max_age_days,
                "has_data": adv_count > 0,
                "advisories_count": adv_count,
            }
