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
from kelan.intel.sources import (
    ADAPTER_REGISTRY,
    PRO_UPGRADE_MSG,
    SourceConfig,
    SourcesManager,
    get_adapter,
)
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
                err_console = Console(stderr=True)
                err_console.print(f"[bold red]✗ Bundle verification failed:[/bold red] {e}")
                return 1
            except Exception as e:
                err_console = Console(stderr=True)
                err_console.print(f"[bold red]✗ Failed to import bundle:[/bold red] {e}")
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
        err_console = Console(stderr=True)
        err_console.print(f"[bold red]✗ Export failed:[/bold red] {e}")
        return 1
    finally:
        store.close()


def cmd_sources(
    argv: list[str] | None = None,
    *,
    console: Console | None = None,
    db: str | None = None,
    **kwargs: Any,
) -> int:
    """Manage custom intelligence sources (rss, json-feed, local-doc)."""
    args_list = list(argv) if argv is not None else []
    c = console or Console()

    if not args_list or args_list[0] in ("-h", "--help", "help"):
        print(
            "usage: kelan intel sources <list | add <name> --type <type> --url <url> | remove <name> | test <name>>\n\n"
            "subcommands:\n"
            "  list                         list all configured custom intelligence sources\n"
            "  add <name> --type <t> --url <u>  add a new custom source (types: rss, json-feed, local-doc)\n"
            "  remove <name>                remove a configured custom source\n"
            "  test <name>                  dry-run fetch & parse without writing to database\n\n"
            "options:\n"
            "  --schema-hint <path>         optional path to JSON schema/field mapping (json-feed)\n"
            "  --allow-local                allow private/loopback IP ranges (SSRF bypass)"
        )
        return 0

    action = args_list[0].lower()
    rest = args_list[1:]
    mgr = SourcesManager()

    if action == "list":
        sources = mgr.list_sources()
        if not sources:
            c.print(
                "[dim]No custom intelligence sources configured.[/dim]\n"
                "Add one using: [bold cyan]kelan intel sources add <name> --type <rss|json-feed|local-doc> --url <url>[/bold cyan]"
            )
            return 0

        from rich.table import Table

        table = Table(title="Custom Intelligence Sources (Community Edition)")
        table.add_column("Name", style="bold cyan")
        table.add_column("Type", style="magenta")
        table.add_column("URL / Target", style="green")
        table.add_column("Allow Local", justify="center")
        table.add_column("Added At", style="dim")

        for s in sources:
            table.add_row(
                s.name,
                s.type,
                s.url,
                "✓" if s.allow_local else "✗",
                s.added_at[:19] if s.added_at else "",
            )
        c.print(table)
        return 0

    elif action == "add":
        if not rest:
            print("usage: kelan intel sources add <name> --type <rss|json-feed|local-doc> --url <url> [--schema-hint <path>] [--allow-local]")
            return 2

        name = rest[0]
        if name.startswith("-"):
            print("kelan: source name required as first argument before flags.", file=sys.stderr)
            return 2

        import argparse

        parser = argparse.ArgumentParser(prog="kelan intel sources add")
        parser.add_argument("name")
        parser.add_argument("--type", "-t", required=True, help="Source type: rss, json-feed, or local-doc")
        parser.add_argument("--url", "-u", required=True, help="URL for feed or file path for local-doc")
        parser.add_argument("--schema-hint", help="Path to JSON schema or field mapping hint")
        parser.add_argument("--allow-local", action="store_true", help="Allow private/loopback IP ranges (SSRF bypass)")
        parser.add_argument("--description", "-d", default="", help="Optional source description")

        try:
            parsed_args = parser.parse_args(rest)
        except SystemExit:
            return 2

        src_type = parsed_args.type.lower()
        if src_type in ("html", "web", "website", "scrape"):
            c.print(f"[bold red]✗ {PRO_UPGRADE_MSG}[/bold red]")
            return 1

        if src_type not in ADAPTER_REGISTRY:
            valid_types = ", ".join(sorted(ADAPTER_REGISTRY.keys()))
            c.print(f"[bold red]✗ Unsupported source type '{parsed_args.type}'. Supported types: {valid_types}.[/bold red]")
            return 2

        config = SourceConfig(
            name=parsed_args.name,
            type=src_type,
            url=parsed_args.url,
            schema_hint=parsed_args.schema_hint,
            allow_local=parsed_args.allow_local,
            description=parsed_args.description,
        )

        try:
            adapter = get_adapter(config)
            val_ok, val_err = adapter.validate()
            if not val_ok:
                c.print(f"[bold red]✗ Validation failed:[/bold red] {val_err}")
                return 1
        except Exception as e:
            c.print(f"[bold red]✗ Validation failed:[/bold red] {e}")
            return 1

        mgr.add_source(config)
        c.print(f"[bold green]✓ Added intelligence source:[/bold green] [bold cyan]{config.name}[/bold cyan] ({config.type})")
        return 0

    elif action == "remove":
        if not rest:
            print("usage: kelan intel sources remove <name>")
            return 2
        name = rest[0]
        if mgr.remove_source(name):
            c.print(f"[bold green]✓ Removed intelligence source:[/bold green] {name}")
            return 0
        else:
            c.print(f"[bold red]✗ Source '{name}' not found.[/bold red]")
            return 1

    elif action == "test":
        if not rest:
            print("usage: kelan intel sources test <name>")
            return 2
        name = rest[0]
        test_config = mgr.get_source(name)
        if not test_config:
            c.print(f"[bold red]✗ Source '{name}' not found in configuration.[/bold red]")
            return 1

        c.print(f"[bold cyan]Testing intelligence source '{name}' (dry-run)...[/bold cyan]")
        try:
            adapter = get_adapter(test_config)
            result = _run_async(adapter.test())
            if result.get("status") == "success":
                count = result.get("records_count", 0)
                c.print(f"[bold green]✓ Dry-run succeeded:[/bold green] Parsed [bold]{count}[/bold] items from {test_config.url}")
                samples = result.get("sample_items", [])
                if samples:
                    from rich.table import Table

                    t = Table(title=f"Sample Items from '{name}'")
                    t.add_column("ID", style="bold")
                    t.add_column("Title", style="cyan")
                    t.add_column("Severity")
                    t.add_column("Published", style="dim")
                    for s in samples:
                        t.add_row(
                            s.get("id", "")[:30],
                            s.get("title", "")[:50],
                            s.get("severity", ""),
                            str(s.get("published_at", ""))[:19],
                        )
                    c.print(t)
                c.print("[dim]Dry-run test complete. No items were written to the database.[/dim]")
                return 0
            else:
                c.print(f"[bold red]✗ Dry-run failed:[/bold red] {result.get('error')}")
                return 1
        except Exception as e:
            c.print(f"[bold red]✗ Dry-run failed:[/bold red] {e}")
            return 1
    else:
        print(f"kelan intel sources: unknown action '{action}'. Choose 'list', 'add', 'remove', or 'test'.", file=sys.stderr)
        return 2


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
            "usage: kelan intel <trending | search <query> | sources <list|add|remove|test>>\n\n"
            "subcommands:\n"
            "  trending  display recently added KEVs, 7-day EPSS risers, and scan matches\n"
            "  search    search advisories by CVE, GHSA, or package name\n"
            "  sources   manage custom intelligence sources (rss, json-feed, local-doc)"
        )
        return 0

    if args_list and args_list[0] in ("-h", "--help", "help"):
        print(
            "usage: kelan intel <trending | search <query> | sources <list|add|remove|test>>\n\n"
            "subcommands:\n"
            "  trending  display recently added KEVs, 7-day EPSS risers, and scan matches\n"
            "  search    search advisories by CVE, GHSA, or package name\n"
            "  sources   manage custom intelligence sources (rss, json-feed, local-doc)"
        )
        return 0

    if not effective_subcmd:
        effective_subcmd = args_list[0] if args_list else "trending"
        subargs = args_list[1:]
    else:
        subargs = args_list

    if effective_subcmd == "sources":
        return cmd_sources(subargs, console=console, db=db, **kwargs)

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
            print(f"kelan intel: unknown subcommand '{effective_subcmd}'. Choose 'trending', 'search', or 'sources'.", file=sys.stderr)
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
    elif first == "sources":
        return cmd_sources(args_list[1:], **kwargs)
    else:
        return cmd_intel(args_list, **kwargs)


if __name__ == "__main__":
    sys.exit(main())
