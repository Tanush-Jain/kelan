# ══ Kelan Intelligence CLI ══════════════════════════════════════════════════════
# License: MIT License (https://opensource.org/licenses/MIT)

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import Any

from rich.console import Console

from kelan.intel.bundle import BundleVerificationError, export_bundle, import_bundle
from kelan.intel.db import IntelStore
from kelan.intel.trending import show_search, show_trending
from kelan.intel.updater import IntelUpdater


def _run_async(coro: Any) -> Any:
    """Safely runs an async coroutine even if an event loop is already active."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()
    return asyncio.run(coro)


def cmd_update(
    argv: list[str] | None = None,
    *,
    offline_bundle: str | None = None,
    sources: list[str] | str | None = None,
    nvd_key: str | None = None,
    nvd_api_key: str | None = None,
    db: str | None = None,
    console: Console | None = None,
    **kwargs: Any,
) -> int:
    """Pull incremental vulnerability intelligence updates or import offline bundle."""
    args_list = list(argv) if argv is not None else []
    if args_list and args_list[0].lower() in ("update", "up"):
        args_list = args_list[1:]

    parser = argparse.ArgumentParser(
        prog="kelan update",
        description="Pull incremental vulnerability intelligence updates or import offline bundle.",
    )
    parser.add_argument(
        "--offline-bundle",
        "-b",
        default=offline_bundle,
        help="Path to an air-gapped Ed25519-signed offline intelligence bundle (.zip)",
    )
    parser.add_argument(
        "--sources",
        "-s",
        help="Comma-separated intelligence sources to sync (cisa_kev, epss, osv, ghsa, nvd)",
    )
    parser.add_argument(
        "--nvd-key",
        default=nvd_key or nvd_api_key,
        help="Optional NVD API key to increase rate limit",
    )
    parser.add_argument(
        "--db",
        default=db,
        help="Optional path to local intelligence database",
    )

    args = parser.parse_args(args_list)
    c = console or Console()

    # Allow keyword overrides to take precedence if passed directly
    bundle_path = offline_bundle or args.offline_bundle
    target_db = db or args.db
    key_val = nvd_key or nvd_api_key or args.nvd_key

    # Resolve sources list
    selected_sources: list[str] | None = None
    if sources is not None:
        if isinstance(sources, str):
            selected_sources = [s.strip() for s in sources.split(",") if s.strip()]
        else:
            selected_sources = list(sources)
    elif args.sources:
        selected_sources = [s.strip() for s in args.sources.split(",") if s.strip()]

    store = IntelStore(target_db)

    try:
        if bundle_path:
            c.print(f"[bold cyan]Importing offline intelligence bundle:[/bold cyan] {bundle_path}")
            try:
                res = import_bundle(bundle_path, store)
                c.print(
                    f"[bold green]✓ Bundle verified & imported successfully![/bold green]\n"
                    f"  Advisories imported: {res['imported_advisories']}\n"
                    f"  Bundle created at: {res['bundle_created_at']}"
                )
                return 0
            except BundleVerificationError as e:
                c.print(f"[bold red]✗ Bundle verification failed:[/bold red] {e}", file=sys.stderr)
                return 1
            except Exception as e:
                c.print(f"[bold red]✗ Failed to import bundle:[/bold red] {e}", file=sys.stderr)
                return 1

        # Online incremental sync
        c.print("[bold cyan]Connecting to vulnerability feeds...[/bold cyan]")
        updater = IntelUpdater(store=store, nvd_api_key=key_val)
        _run_async(updater.update(sources=selected_sources, console=c))
        return 0
    finally:
        store.close()


def cmd_export_bundle(
    argv: list[str] | None = None,
    *,
    output: str | None = None,
    output_path: str | None = None,
    db: str | None = None,
    priv_key: str | None = None,
    private_key: str | None = None,
    console: Console | None = None,
    **kwargs: Any,
) -> int:
    """Export an Ed25519-signed offline vulnerability intelligence bundle for air-gapped systems."""
    args_list = list(argv) if argv is not None else []
    if args_list and args_list[0].lower() in ("export-bundle", "export_bundle", "export"):
        args_list = args_list[1:]

    default_output = output or output_path or "kelan-intel-bundle.zip"
    default_key = priv_key or private_key

    parser = argparse.ArgumentParser(
        prog="kelan export-bundle",
        description="Export an Ed25519-signed offline vulnerability intelligence bundle for air-gapped systems.",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=default_output,
        help="Destination path for the zip bundle (default: kelan-intel-bundle.zip)",
    )
    parser.add_argument(
        "--db",
        default=db,
        help="Optional path to source intelligence database",
    )
    parser.add_argument(
        "--priv-key",
        default=default_key,
        help="Optional base64-encoded Ed25519 private key for bundle signing",
    )

    args = parser.parse_args(args_list)
    c = console or Console()

    out_dest = output or output_path or args.output
    signing_key = priv_key or private_key or args.priv_key
    target_db = db or args.db

    store = IntelStore(target_db)
    try:
        c.print(f"[bold cyan]Exporting intelligence bundle to:[/bold cyan] {out_dest}")
        final_path = export_bundle(out_dest, store, private_key=signing_key)
        c.print(
            f"[bold green]✓ Bundle exported and signed successfully![/bold green]\n"
            f"  Bundle path: {final_path}\n"
            f"  Size: {final_path.stat().st_size} bytes"
        )
        return 0
    except Exception as e:
        c.print(f"[bold red]✗ Export failed:[/bold red] {e}", file=sys.stderr)
        return 1
    finally:
        store.close()


def cmd_intel(
    argv: list[str] | None = None,
    *,
    subcommand: str | None = None,
    subcmd: str | None = None,
    query: str | None = None,
    db: str | None = None,
    console: Console | None = None,
    **kwargs: Any,
) -> int:
    """Inspect local threat intelligence: trending exploits or advisory keyword/CVE search."""
    args_list = list(argv) if argv is not None else []
    if args_list and args_list[0].lower() == "intel":
        args_list = args_list[1:]

    effective_subcmd = subcommand or subcmd
    effective_query = query

    if not args_list and not effective_subcmd and not effective_query:
        print(
            "usage: kelan intel <trending | search <query>>\n\n"
            "subcommands:\n"
            "  trending  display recently added KEVs, 7-day EPSS risers, and scan matches\n"
            "  search    search advisories by CVE, GHSA, or package name"
        )
        return 0

    if args_list and args_list[0] in ("-h", "--help", "help"):
        print(
            "usage: kelan intel <trending | search <query>>\n\n"
            "subcommands:\n"
            "  trending  display recently added KEVs, 7-day EPSS risers, and scan matches\n"
            "  search    search advisories by CVE, GHSA, or package name"
        )
        return 0

    if not effective_subcmd:
        effective_subcmd = args_list[0] if args_list else "trending"
        subargs = args_list[1:]
    else:
        subargs = args_list

    if not effective_query and subargs:
        effective_query = " ".join(subargs)

    c = console or Console()
    store = IntelStore(db)

    try:
        if effective_subcmd == "trending":
            show_trending(store, c)
            return 0
        elif effective_subcmd == "search":
            if not effective_query:
                print("usage: kelan intel search <cve|ghsa|package>")
                return 2
            show_search(store, effective_query, c)
            return 0
        else:
            print(f"kelan intel: unknown subcommand '{effective_subcmd}'. Choose 'trending' or 'search'.", file=sys.stderr)
            return 2
    finally:
        store.close()


def main(argv: list[str] | None = None, **kwargs: Any) -> int:
    """Universal dispatcher for kelan.intel.cli supporting both CLI lists and keyword invocations."""
    args_list = list(argv) if argv is not None else sys.argv[1:]
    if not args_list:
        if kwargs:
            if "offline_bundle" in kwargs or "sources" in kwargs:
                return cmd_update(args_list, **kwargs)
            elif "output" in kwargs or "output_path" in kwargs:
                return cmd_export_bundle(args_list, **kwargs)
            elif "query" in kwargs or "subcommand" in kwargs or "subcmd" in kwargs:
                return cmd_intel(args_list, **kwargs)
        return cmd_intel(args_list, **kwargs)

    first = args_list[0].lower()
    if first in ("update", "up"):
        return cmd_update(args_list[1:], **kwargs)
    elif first in ("export-bundle", "export_bundle", "export"):
        return cmd_export_bundle(args_list[1:], **kwargs)
    elif first in ("intel", "trending", "search"):
        return cmd_intel(args_list, **kwargs)
    else:
        return cmd_intel(args_list, **kwargs)


if __name__ == "__main__":
    sys.exit(main())
