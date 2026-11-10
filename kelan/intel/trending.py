from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from kelan.intel.db import IntelStore


def show_trending(store: IntelStore, console: Console | None = None) -> None:
    c = console or Console()

    # 1. Newly Added KEV Entries
    kev_entries = store.get_trending_kev(limit=10)
    t_kev = Table(title="[bold red]Newly Added CISA KEV Exploits[/bold red]", expand=True)
    t_kev.add_column("CVE ID", style="bold cyan", width=16)
    t_kev.add_column("Vulnerability / Title", style="white")
    t_kev.add_column("Date Added", justify="center", width=12)
    t_kev.add_column("CVSS", justify="right", width=6)
    t_kev.add_column("EPSS", justify="right", width=8)

    if not kev_entries:
        t_kev.add_row("-", "[dim]No KEV entries recorded in store. Run 'kelan update' to sync feeds.[/dim]", "-", "-", "-")
    else:
        for k in kev_entries:
            cvss_str = f"{k.get('cvss_score'):.1f}" if k.get("cvss_score") is not None else "-"
            epss_str = f"{k.get('epss_score'):.3f}" if k.get("epss_score") is not None else "-"
            t_kev.add_row(
                k["id"],
                k.get("title") or "Known Exploited Vulnerability",
                k.get("kev_date_added") or "-",
                cvss_str,
                epss_str,
            )
    c.print(t_kev)
    c.print()

    # 2. EPSS Top 7-Day Risers
    epss_risers = store.get_trending_epss(limit=10, days=7)
    t_epss = Table(title="[bold yellow]EPSS Scores — Highest 7-Day Risers[/bold yellow]", expand=True)
    t_epss.add_column("CVE ID", style="bold cyan", width=16)
    t_epss.add_column("Current EPSS", justify="right", width=14)
    t_epss.add_column("7d Ago EPSS", justify="right", width=14)
    t_epss.add_column("7d Delta", justify="right", style="bold magenta", width=12)

    if not epss_risers:
        t_epss.add_row("-", "-", "-", "[dim]No EPSS history recorded yet.[/dim]")
    else:
        for r in epss_risers:
            cur_s = f"{r.get('current_score', 0):.4f}" if r.get("current_score") is not None else "-"
            prev_s = f"{r.get('previous_score', 0):.4f}" if r.get("previous_score") is not None else "-"
            delta_val = r.get("delta", 0.0)
            delta_str = f"+{delta_val:.4f}" if delta_val > 0 else f"{delta_val:.4f}"
            t_epss.add_row(
                r["cve"],
                cur_s,
                prev_s,
                delta_str,
            )
    c.print(t_epss)
    c.print()

    # 3. Advisories Matching Scanned Packages
    scanned_matches = store.get_trending_scanned(limit=10)
    t_scanned = Table(title="[bold green]Advisories Affecting Your Recently Scanned Packages[/bold green]", expand=True)
    t_scanned.add_column("Package", style="bold cyan", width=18)
    t_scanned.add_column("Version", justify="center", width=10)
    t_scanned.add_column("Ecosystem", width=10)
    t_scanned.add_column("Advisory ID", style="bold", width=16)
    t_scanned.add_column("Title", style="white")
    t_scanned.add_column("Severity", justify="center", width=10)
    t_scanned.add_column("KEV", justify="center", width=6)
    t_scanned.add_column("EPSS", justify="right", width=8)

    if not scanned_matches:
        t_scanned.add_row("-", "-", "-", "-", "[dim]No recent scanned package vulnerabilities found.[/dim]", "-", "-", "-")
    else:
        for sm in scanned_matches:
            sev = sm.get("severity", "MEDIUM")
            color = "red" if sev in ("CRITICAL", "HIGH") else "yellow" if sev == "MEDIUM" else "blue"
            kev_badge = "[red]YES[/red]" if sm.get("is_kev") else "[dim]NO[/dim]"
            epss_str = f"{sm.get('epss_score'):.3f}" if sm.get("epss_score") is not None else "-"
            t_scanned.add_row(
                sm["package_name"],
                sm["version"],
                sm["ecosystem"],
                sm["advisory_id"],
                (sm.get("title") or "")[:45],
                f"[{color}]{sev}[/{color}]",
                kev_badge,
                epss_str,
            )
    c.print(t_scanned)


def show_search(store: IntelStore, query: str, console: Console | None = None) -> None:
    c = console or Console()
    results = store.search(query)

    if not results:
        c.print(Panel(f"[yellow]No vulnerability advisories found matching '{query}'.[/yellow]"))
        return

    c.print(f"[bold]Found {len(results)} advisory matches for '{query}':[/bold]\n")

    for adv in results:
        sev_color = "red" if adv.severity in ("CRITICAL", "HIGH") else "yellow" if adv.severity == "MEDIUM" else "blue"
        kev_badge = "[bold red]🚨 CISA KEV (Known Exploited)[/bold red]" if adv.is_kev else "[dim]Not in KEV[/dim]"
        epss_info = f"EPSS: [bold]{adv.epss_score:.4f}[/bold]" if adv.epss_score is not None else "EPSS: N/A"
        if adv.epss_percentile is not None:
            epss_info += f" ({adv.epss_percentile * 100:.1f}th percentile)"

        cvss_info = f"CVSS: [bold]{adv.cvss_score}[/bold]" if adv.cvss_score is not None else "CVSS: N/A"
        if adv.cvss_vector:
            cvss_info += f" ({adv.cvss_vector})"

        alias_str = ", ".join(adv.aliases) if adv.aliases else "None"

        pkg_lines = []
        for p in adv.packages:
            fix_str = f"< {p.fixed}" if p.fixed else "unpatched"
            pkg_lines.append(f"  • [cyan]{p.ecosystem}[/cyan]: [bold]{p.package_name}[/bold] (introduced: {p.introduced}, fixed: {fix_str})")
        pkg_display = "\n".join(pkg_lines) if pkg_lines else "  [dim]No specific package ranges recorded[/dim]"

        desc_short = (adv.description[:300] + "...") if len(adv.description) > 300 else (adv.description or "No description provided.")

        c.print(Panel(
            f"[bold cyan]{adv.id}[/bold cyan] — [{sev_color}]{adv.severity}[/{sev_color}] "
            f"(Source: [dim]{adv.source}[/dim])\n"
            f"[bold]{adv.title}[/bold]\n\n"
            f"{desc_short}\n\n"
            f"• [dim]Status:[/dim] {cvss_info} | {epss_info} | {kev_badge}\n"
            f"• [dim]Aliases:[/dim] {alias_str}\n"
            f"• [dim]Affected Packages:[/dim]\n{pkg_display}\n"
            f"• [dim]Dates:[/dim] Published: {adv.published_at or 'N/A'} | Modified: {adv.modified_at or 'N/A'} | Fetched: {adv.fetched_at or 'N/A'}",
            expand=False,
        ))

