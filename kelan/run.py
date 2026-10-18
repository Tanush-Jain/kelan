
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Optional

from kelan.core.finding import Severity, Confidence
from kelan.core.plugin import PluginRegistry, Scheduler, ScanTarget, ScopeKind, ScanConfig
from kelan.plugins import register_all


def detect_scope(target: str) -> ScopeKind:
    if target.endswith(".git") or "git@" in target:
        return ScopeKind.REPO
    if target.startswith(("http://", "https://")):
        return ScopeKind.URL
    if os.path.exists(target):
        return ScopeKind.CODEBASE
    return ScopeKind.HOST


def main(argv: Optional[list[str]] = None) -> int:
    argv = list(argv) if argv is not None else sys.argv[1:]
    
    parser = argparse.ArgumentParser(description="Kelan — AI-native plugin scheduler")
    parser.add_argument("target", nargs="?", help="Scan target (path, URL, host, or git URL)")
    parser.add_argument("--only", help="Comma-separated list of plugins to run")
    parser.add_argument("--skip", help="Comma-separated list of plugins to skip")
    parser.add_argument("--json", help="Path to write JSON findings report")
    parser.add_argument("--sarif", help="Path to write SARIF findings report")
    parser.add_argument("--html", help="Path to write HTML findings report")
    parser.add_argument("--ci-gate", choices=["critical", "high", "medium", "low"], help="Fail build if findings exist at/above this severity")
    parser.add_argument("--show", action="store_true", help="Print findings cleanly to console")
    parser.add_argument("--plugins", action="store_true", help="List all registered plugins and exit")
    
    args = parser.parse_args(argv)
    
    registry = PluginRegistry()
    register_all(registry)
    
    if args.plugins:
        print("Registered Plugins:")
        for name in registry.names():
            p = registry.get(name)
            print(f"  - {p.name} (v{p.version}): {p.description}")
        return 0
        
    if not args.target:
        parser.print_help()
        return 2
        
    kind = detect_scope(args.target)
    target = ScanTarget(kind=kind, value=args.target)
    
    only_set = {p.strip() for p in args.only.split(",")} if args.only else None
    skip_set = {p.strip() for p in args.skip.split(",")} if args.skip else None
    
    config = ScanConfig(values={
        "use_llm": True,
        "ollama": {
            "endpoint": "http://127.0.0.1:11434",
            "model": "qwen2.5-coder:latest"
        }
    })
    
    scheduler = Scheduler(registry, config=config)
    
    try:
        findings, results = asyncio.run(scheduler.run(target, only=only_set, skip=skip_set))
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        scheduler.cleanup()
        return 130
    except Exception as e:
        print(f"\nScan failed: {e}")
        scheduler.cleanup()
        return 2
        
    if args.show:
        try:
            from rich.console import Console
            from rich.table import Table
            from rich.panel import Panel
            console = Console()
            
            console.print(Panel(f"[bold cyan]Scan Results for {target.display()}[/bold cyan]", expand=False))
            
            table = Table(title="Findings Summary")
            table.add_column("Severity", justify="left")
            table.add_column("CWE", justify="left")
            table.add_column("Title", justify="left")
            table.add_column("Plugin", justify="left")
            table.add_column("Location", justify="left")
            
            for f in findings:
                color = "red" if f.severity in (Severity.CRITICAL, Severity.HIGH) else "yellow" if f.severity == Severity.MEDIUM else "blue"
                table.add_row(
                    f"[{color}]{f.severity.value}[/{color}]",
                    f.cwe,
                    f.title,
                    f.plugin,
                    f.location
                )
            console.print(table)
            
            for f in findings:
                console.print(f"\n[bold]{f.title}[/bold] ({f.cwe}) — {f.plugin}")
                console.print(f"  [dim]Severity:[/dim] {f.severity.value}  [dim]Confidence:[/dim] {f.confidence.value}")
                console.print(f"  [dim]Location:[/dim] {f.location}")
                if f.remediation:
                    console.print(f"  [green]Remediation:[/green] {f.remediation}")
                for e in f.evidence:
                    console.print(f"  [cyan]Evidence ({e.kind}):[/cyan] {e.detail}")
                    if e.snippet:
                        console.print(f"    [dim]{e.snippet}[/dim]")
        except ImportError:
            width = 72
            print("=" * width)
            print("KELAN UNIFIED SCAN REPORT")
            print("=" * width)
            for f in findings:
                print(f"[{f.severity.value}] {f.cwe} — {f.title} ({f.plugin})")
                print(f"  Location: {f.location}")
                for e in f.evidence:
                    print(f"  Evidence [{e.kind}]: {e.detail}")
            print("=" * width)
            
    if args.json:
        findings.write_json(args.json)
        print(f"[*] wrote JSON report to {args.json}")
        
    if args.sarif:
        sarif_data = findings.to_sarif()
        with open(args.sarif, "w") as fh:
            json.dump(sarif_data, fh, indent=2)
        print(f"[*] wrote SARIF report to {args.sarif}")
        
    if args.html:
        findings.write_html(args.html)
        print(f"[*] wrote HTML report to {args.html}")
        
    scheduler.cleanup()
    
    if args.ci_gate:
        code = findings.gate(args.ci_gate)
        print(f"🧪 CI gate ({args.ci_gate}): {'FAIL' if code else 'PASS'}")
        return code
        
    return 0


if __name__ == "__main__":
    sys.exit(main())

