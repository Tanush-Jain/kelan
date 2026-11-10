from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from kelan.intel.db import IntelStore

# Default embedded public key for Kelan intelligence bundle verification
DEFAULT_BUNDLE_PUB_B64 = "K+7mJYEqbkbjWbqX9K7UgSrm/N/pchNMuI0tzITh9l8="

# Default dev signing private key (used if no external key is supplied)
DEFAULT_DEV_PRIV_B64 = "mAqCe7gV8LYfXtYA2kimwGCjPrxIwsQz4E2pC55Lvt8="


class BundleVerificationError(Exception):
    """Raised when an offline intelligence bundle fails cryptographic or checksum verification."""


def _compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def export_bundle(
    output_path: str | Path,
    store: IntelStore,
    private_key: Ed25519PrivateKey | bytes | str | None = None,
) -> Path:
    out_file = Path(output_path).expanduser().resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)

    # Determine private key
    if private_key is None:
        priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(DEFAULT_DEV_PRIV_B64))
    elif isinstance(private_key, Ed25519PrivateKey):
        priv = private_key
    elif isinstance(private_key, bytes):
        priv = Ed25519PrivateKey.from_private_bytes(private_key)
    elif isinstance(private_key, str):
        priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_key))
    else:
        raise ValueError("Invalid private key format")

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        dump_db = tmp_path / "intel.db"

        # Export clean snapshot using SQLite backup API
        bck_conn = sqlite3.connect(str(dump_db))
        with bck_conn:
            store._conn.backup(bck_conn)
        bck_conn.close()

        db_bytes = dump_db.read_bytes()
        db_hash = _compute_sha256(db_bytes)

        # Collect summary counts
        adv_count = store._conn.execute("SELECT count(*) as c FROM advisories").fetchone()["c"]
        pkg_count = store._conn.execute("SELECT count(*) as c FROM packages").fetchone()["c"]
        sources = [
            r["source"]
            for r in store._conn.execute("SELECT DISTINCT source FROM sync_state").fetchall()
        ]

        manifest = {
            "schema_version": "1.0",
            "created_at": datetime.now(UTC).isoformat(),
            "tool": "kelan",
            "files": {
                "intel.db": {
                    "sha256": db_hash,
                    "size_bytes": len(db_bytes),
                }
            },
            "summary": {
                "advisories_count": adv_count,
                "packages_count": pkg_count,
                "sources": sources,
            },
        }

        manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
        signature = priv.sign(manifest_bytes)

        # Write zip archive
        with zipfile.ZipFile(out_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("manifest.json", manifest_bytes)
            zf.writestr("manifest.sig", signature)
            zf.writestr("intel.db", db_bytes)

    return out_file


def import_bundle(
    bundle_path: str | Path,
    target_store: IntelStore,
    public_key: Ed25519PublicKey | bytes | str | None = None,
) -> dict[str, Any]:
    b_file = Path(bundle_path).expanduser().resolve()
    if not b_file.exists():
        raise FileNotFoundError(f"Offline bundle not found: {b_file}")

    # Determine public key
    if public_key is None:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(DEFAULT_BUNDLE_PUB_B64))
    elif isinstance(public_key, Ed25519PublicKey):
        pub = public_key
    elif isinstance(public_key, bytes):
        pub = Ed25519PublicKey.from_public_bytes(public_key)
    elif isinstance(public_key, str):
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key))
    else:
        raise ValueError("Invalid public key format")

    try:
        zf = zipfile.ZipFile(b_file, "r")
    except zipfile.BadZipFile as e:
        raise BundleVerificationError(f"Corrupt or invalid zip bundle: {e}") from e

    with zf:
        namelist = set(zf.namelist())
        if "manifest.json" not in namelist or "manifest.sig" not in namelist or "intel.db" not in namelist:
            raise BundleVerificationError("Bundle is missing required files (manifest.json, manifest.sig, intel.db)")

        manifest_bytes = zf.read("manifest.json")
        sig_bytes = zf.read("manifest.sig")
        db_bytes = zf.read("intel.db")

        # 1. Cryptographic Ed25519 Signature Verification
        try:
            pub.verify(sig_bytes, manifest_bytes)
        except InvalidSignature as e:
            raise BundleVerificationError("Ed25519 signature verification failed: bundle may be forged or tampered") from e

        # 2. Manifest SHA-256 verification
        try:
            manifest = json.loads(manifest_bytes.decode("utf-8"))
        except json.JSONDecodeError as e:
            raise BundleVerificationError("Invalid manifest JSON") from e

        expected_db_info = manifest.get("files", {}).get("intel.db")
        if not expected_db_info:
            raise BundleVerificationError("Manifest missing hash for intel.db")

        actual_hash = _compute_sha256(db_bytes)
        if actual_hash != expected_db_info.get("sha256"):
            raise BundleVerificationError(
                f"Checksum mismatch for intel.db: expected {expected_db_info.get('sha256')}, got {actual_hash}"
            )

        # 3. Import data into target store
        with tempfile.TemporaryDirectory() as tmp_dir:
            temp_db_path = Path(tmp_dir) / "imported.db"
            temp_db_path.write_bytes(db_bytes)

            src_conn = sqlite3.connect(str(temp_db_path))
            src_conn.row_factory = sqlite3.Row

            imported_count = 0
            with src_conn:
                rows = src_conn.execute("SELECT * FROM advisories").fetchall()
                for r in rows:
                    adv = target_store._row_to_advisory(r, conn=src_conn)
                    target_store.upsert_advisory(adv)
                    imported_count += 1

                # Copy sync state
                sync_rows = src_conn.execute("SELECT * FROM sync_state").fetchall()
                for sr in sync_rows:
                    target_store._conn.execute(
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
                            sr["source"],
                            sr["etag"],
                            sr["last_modified"],
                            sr["last_sync_time"],
                            sr["records_count"],
                            sr["status"],
                        ),
                    )

            src_conn.close()

        # Update offline_bundle sync state
        target_store._conn.execute(
            """
            INSERT INTO sync_state (source, etag, last_modified, last_sync_time, records_count, status)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(source) DO UPDATE SET
                last_sync_time=excluded.last_sync_time,
                records_count=excluded.records_count,
                status=excluded.status
            """,
            (
                "offline_bundle",
                actual_hash[:16],
                manifest.get("created_at"),
                datetime.now(UTC).isoformat(),
                imported_count,
                "verified & imported",
            ),
        )

        return {
            "status": "success",
            "imported_advisories": imported_count,
            "bundle_created_at": manifest.get("created_at"),
            "manifest_summary": manifest.get("summary", {}),
        }
