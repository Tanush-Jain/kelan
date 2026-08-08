


from __future__ import annotations

import sys

import structlog
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

log = structlog.get_logger()


def _err(msg: str, code: int = 2) -> int:
    print(f"kelan: {msg}", file=sys.stderr)
    return code


def _delegate() -> int | None:

    from kelan import run
    return run.main()


def cmd_menu() -> int:

    console = Console()
    while True:
        console.print(Panel.fit(
            "[bold cyan]Kelan[/bold cyan] — AI-native security scanner\n"
            "[dim]sast | git | dast | recon | run | exit[/dim]"))
        choice = Prompt.ask("Select", choices=[
            "sast", "recon", "run", "git", "exit"])
        if choice == "exit":
            return 0
        if choice == "git":
            from rich.prompt import Prompt as P
            repo = P.ask("Remote git URL")
            return _run_target(repo)
        if choice in ("sast", "run", "recon"):
            target = Prompt.ask(f"{choice} target (path | url | host)")
            return _run_target(target)
    return 0


def _run_target(target: str) -> int:
    sys.argv = ["kelan", target, "--show"]
    return _delegate() or 0


def _usage() -> int:
    print(
        "usage: kelan <command> [options]\n"
        "commands:\n"
        "  menu           interactive dispatcher\n"
        "  run <t>        scan a url / repo / dir / host (plugin scheduler)\n"
        "  sast <path>    static analysis of a codebase\n"
        "  git <url>      clone + statically audit a remote repo\n"
        "  dast <url>     dynamic app scan (crawl + probes)\n"
        "  recon <host>   open-port discovery (opt-in scanning)\n"
        "  github <url>   GitHub-repo audit shorthand\n"
        "  doctor         check environment readiness\n"
        "  --plugins      list registered plugins\n"
    )
    return 2


def _launch_dashboard() -> None:
    import socket
    import subprocess
    import sys
    import time
    import webbrowser
    from pathlib import Path

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 7681))
        s.close()
        port_free = True
    except OSError:
        port_free = False

    if port_free:
        root = Path(__file__).parent.parent.parent
        dash_dir = root / "kelan-dashboard/dist"
        if not dash_dir.exists():
            dash_dir = root / "kelan-dashboard"
        if dash_dir.exists():
            subprocess.Popen(
                [sys.executable, "-m", "http.server", "7681", "--directory", str(dash_dir)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(0.5)

    try:
        webbrowser.open("http://localhost:7681")
    except Exception:
        pass


def main(argv: list[str] | None = None) -> int:
    argv = list(argv) if argv is not None else sys.argv[1:]
    
    # Launch dashboard for scans, menus, or default invocations
    cmd = argv[0] if argv else ""
    if cmd not in ("-h", "--help", "help", "doctor"):
        _launch_dashboard()

    if not argv:
        return cmd_menu()

    if cmd in ("-h", "--help", "help"):
        return _usage()
    if cmd == "menu":
        return cmd_menu()
    if cmd == "doctor":
        import asyncio

        from kelan.doctor import doctor
        return asyncio.run(doctor())
    if cmd == "--plugins":
        sys.argv = ["kelan", "--plugins"]
        return _delegate() or 0

    if cmd in ("run", "sast", "dast", "recon", "git", "github"):
        sys.argv = ["kelan"] + [*argv[1:], "--show"]
        if cmd == "run":
            sys.argv = ["kelan"] + argv[1:]
        return _delegate() or 0

    sys.argv = ["kelan"] + argv
    return _delegate() or 0


if __name__ == "__main__":
    sys.exit(main())
