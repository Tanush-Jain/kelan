from __future__ import annotations

import argparse
import asyncio
import sys

from rich.console import Console

from kelan.intel.bundle import BundleVerificationError, export_bundle, import_bundle
from kelan.intel.db import IntelStore
from kelan.intel.trending import show_search, show_trending
from kelan.intel.updater import IntelUpdater


def cmd_update(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="kelan update",
        description="Pull incremental vulnerability intelligence updates or import offline bundle.",
    )
    parser.add_argument(
        "--offline-bundle",
        "-b",
        help="Path to an air-gapped Ed25519-signed offline intelligence bundle (.zip)",
    )
    parser.add_argument(
        "--sources",
        "-s",
        help="Comma-separated intelligence sources to sync (cisa_kev, epss, osv, ghsa, nvd)",
    )
    parser.add_argument(
        "--nvd-key",
        help="Optional NVD API key to increase rate limit",
    )
    parser.add_argument(
        "--db",
        help="Optional path to local intelligence database",
    )

    args = parser.parse_args(argv)
    console = Console()

    store = IntelStore(args.db)

    try:
        if args.offline_bundle:
            console.print(f"[bold cyan]Importing offline intelligence bundle:[/bold cyan] {args.offline_bundle}")
            try:
                res = import_bundle(args.offline_bundle, store)
                console.print(
                    f"[bold green]✓ Bundle verified & imported successfully![/bold green]\n"
                    f"  Advisories imported: {res['imported_advisories']}\n"
                    f"  Bundle created at: {res['bundle_created_at']}"
                )
                return 0
            except BundleVerificationError as e:
                console.print(f"[bold red]✗ Bundle verification failed:[/bold red] {e}", file=sys.stderr)
                return 1
            except Exception as e:
                console.print(f"[bold red]✗ Failed to import bundle:[/bold red] {e}", file=sys.stderr)
                return 1

        # Online incremental sync
        console.print("[bold cyan]Connecting to vulnerability feeds...[/bold cyan]")
        sources = [s.strip() for s in args.sources.split(",")] if args.sources else None
        updater = IntelUpdater(store=store, nvd_api_key=args.nvd_key)
        asyncio.run(updater.update(sources=sources, console=console))
        return 0
    finally:
        store.close()


def cmd_export_bundle(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="kelan export-bundle",
        description="Export an Ed25519-signed offline vulnerability intelligence bundle for air-gapped systems.",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="kelan-intel-bundle.zip",
        help="Destination path for the zip bundle (default: kelan-intel-bundle.zip)",
    )
    parser.add_argument(
        "--db",
        help="Optional path to source intelligence database",
    )
    parser.add_argument(
        "--priv-key",
        help="Optional base64-encoded Ed25519 private key for bundle signing",
    )

    args = parser.parse_args(argv)
    console = Console()

    store = IntelStore(args.db)
    try:
        console.print(f"[bold cyan]Exporting intelligence bundle to:[/bold cyan] {args.output}")
        out_path = export_bundle(args.output, store, private_key=args.priv_key)
        console.print(
            f"[bold green]✓ Bundle exported and signed successfully![/bold green]\n"
            f"  Bundle path: {out_path}\n"
            f"  Size: {out_path.stat().st_size} bytes"
        )
        return 0
    except Exception as e:
        console.print(f"[bold red]✗ Export failed:[/bold red] {e}", file=sys.stderr)
        return 1
    finally:
        store.close()


def cmd_intel(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(
            "usage: kelan intel <trending | search <query>>\n\n"
            "subcommands:\n"
            "  trending  display recently added KEVs, 7-day EPSS risers, and scan matches\n"
            "  search    search advisories by CVE, GHSA, or package name"
        )
        return 0

    subcmd = argv[0]
    subargs = argv[1:]
    console = Console()
    store = IntelStore()

    try:
        if subcmd == "trending":
            show_trending(store, console)
            return 0
        elif subcmd == "search":
            if not subargs:
                print("usage: kelan intel search <cve|ghsa|package>")
                return 2
            query = " ".join(subargs)
            show_search(store, query, console)
            return 0
        else:
            print(f"kelan intel: unknown subcommand '{subcmd}'. Choose 'trending' or 'search'.", file=sys.stderr)
            return 2
    finally:
        store.close()

