from __future__ import annotations

from datetime import UTC, datetime

from rich.console import Console
from rich.table import Table

from kelan.intel.db import IntelStore
from kelan.intel.fetchers.base import FetchResult
from kelan.intel.fetchers.cisa import CisaKevFetcher
from kelan.intel.fetchers.epss import EpssFetcher
from kelan.intel.fetchers.ghsa import GhsaFetcher
from kelan.intel.fetchers.nvd import NvdFetcher
from kelan.intel.fetchers.osv import OsvFetcher
from kelan.intel.models import SyncState


class IntelUpdater:
    def __init__(
        self,
        store: IntelStore,
        nvd_api_key: str | None = None,
        github_token: str | None = None,
    ) -> None:
        self.store = store
        self.fetchers = {
            "cisa_kev": CisaKevFetcher(),
            "epss": EpssFetcher(),
            "osv": OsvFetcher(),
            "ghsa": GhsaFetcher(token=github_token),
            "nvd": NvdFetcher(api_key=nvd_api_key),
        }

    async def update(
        self,
        sources: list[str] | None = None,
        console: Console | None = None,
    ) -> list[FetchResult]:
        selected = sources or list(self.fetchers.keys())
        results: list[FetchResult] = []

        now_iso = datetime.now(UTC).isoformat()

        for name in selected:
            fetcher = self.fetchers.get(name)
            if not fetcher:
                continue

            # Execute fetch
            res = await fetcher.fetch(self.store)
            results.append(res)

            # Update sync state in DB
            status_text = res.status
            if res.status == "error" and res.error_message:
                status_text = f"error: {res.error_message[:40]}"

            sync = SyncState(
                source=name,
                etag=res.etag,
                last_modified=res.last_modified,
                last_sync_time=now_iso if res.status in ("success", "not_modified") else None,
                records_count=res.records_count,
                status=status_text,
            )
            self.store.update_sync_state(sync)

        if console is not None:
            self.render_summary(results, console)

        return results

    def render_summary(self, results: list[FetchResult], console: Console) -> None:
        table = Table(title="Vulnerability Intelligence Sync Summary")
        table.add_column("Source", style="cyan", no_wrap=True)
        table.add_column("Status", justify="center")
        table.add_column("Records", justify="right")
        table.add_column("Duration", justify="right")
        table.add_column("Details", style="dim")

        for r in results:
            if r.status == "success":
                status_str = "[bold green]UPDATED[/bold green]"
            elif r.status == "not_modified":
                status_str = "[bold blue]UP-TO-DATE[/bold blue]"
            elif r.status == "skipped":
                status_str = "[dim]SKIPPED[/dim]"
            else:
                status_str = "[bold red]FAILED[/bold red]"

            details = ""
            if r.error_message:
                details = r.error_message
            elif r.etag:
                details = f"ETag: {r.etag[:16]}..."
            elif r.last_modified:
                details = f"Modified: {r.last_modified}"

            table.add_row(
                r.source,
                status_str,
                str(r.records_count),
                f"{r.duration_s:.2f}s",
                details[:50],
            )

        console.print(table)

