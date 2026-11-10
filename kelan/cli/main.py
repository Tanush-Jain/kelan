


from __future__ import annotations

import subprocess
import sys
from typing import Any

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


def _load_extension_commands() -> dict[str, Any]:
    cmds: dict[str, Any] = {}
    try:
        from importlib.metadata import entry_points
        eps = entry_points(group="kelan.commands")
        for ep in eps:
            try:
                fn = ep.load()
                discovered = fn() if callable(fn) else fn
                if isinstance(discovered, dict):
                    cmds.update(discovered)
            except Exception:
                pass
    except Exception:
        pass
    return cmds


def _usage(code: int = 0) -> int:
    exts = _load_extension_commands()
    ext_list = ""
    if exts:
        ext_list = "\npro commands:\n" + "\n".join(f"  {name:<14} (from kelan-pro)" for name in sorted(exts))
    print(
        "usage: kelan <command> [options]\n"
        "commands:\n"
        "  menu           interactive dispatcher\n"
        "  run <t>        scan a url / repo / dir / host (plugin scheduler)\n"
        "  sast <path>    static analysis of a codebase\n"
        "  sca <path>     software composition analysis of dependencies\n"
        "  git <url>      clone + statically audit a remote repo\n"
        "  dast <url>     dynamic app scan (crawl + probes)\n"
        "  recon <host>   open-port discovery (opt-in scanning)\n"
        "  github <url>   GitHub-repo audit shorthand\n"
        "  doctor         check environment readiness\n"
        "  setup          guided first-time environment setup\n"
        "  update         sync vulnerability intelligence feeds\n"
        "  export-bundle  export air-gapped signed intelligence bundle\n"
        "  intel          threat trending & advisory search\n"
        "  --plugins      list registered plugins\n"
        "  --dashboard    launch local web dashboard"
        + ext_list
    )
    return code


def _start_dashboard_server() -> subprocess.Popen | None:
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

    proc = None
    if port_free:
        root = Path(__file__).parent.parent.parent
        dash_dir = root / "kelan-dashboard/dist"
        if not dash_dir.exists():
            dash_dir = root / "kelan-dashboard"
        if dash_dir.exists():
            proc = subprocess.Popen(
                [sys.executable, "-m", "http.server", "7681", "--directory", str(dash_dir)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(0.5)

    try:
        webbrowser.open("http://localhost:7681")
    except Exception:
        pass

    return proc


def _stop_dashboard_server(proc: subprocess.Popen | None) -> None:
    if proc:
        try:
            proc.terminate()
            proc.wait(timeout=2.0)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


def main(argv: list[str] | None = None) -> int:
    argv = list(argv) if argv is not None else sys.argv[1:]
    
    with_dashboard = "--dashboard" in argv
    if with_dashboard:
        argv = [a for a in argv if a != "--dashboard"]

    dash_proc = None
    if with_dashboard:
        dash_proc = _start_dashboard_server()
        if not argv:
            print("Kelan dashboard running at http://localhost:7681 (press Ctrl+C to stop)")
            try:
                if dash_proc:
                    dash_proc.wait()
                else:
                    import time
                    while True:
                        time.sleep(1)
            except KeyboardInterrupt:
                pass
            finally:
                _stop_dashboard_server(dash_proc)
            return 0

    try:
        cmd = argv[0] if argv else ""
        if not argv:
            return cmd_menu()

        if cmd in ("-h", "--help", "help"):
            return _usage()

        ext_cmds = _load_extension_commands()
        if cmd in ext_cmds:
            return ext_cmds[cmd](argv[1:])
        if cmd in ("enforce", "agent", "simulate", "license", "rbac"):
            print(
                f"kelan: command '{cmd}' requires the kelan-pro package.\n"
                f"Install it with: pip install kelan-pro",
                file=sys.stderr,
            )
            return 1

        if cmd == "menu":
            return cmd_menu()
        if cmd == "doctor":
            import asyncio

            from kelan.doctor import doctor
            return asyncio.run(doctor())
        if cmd == "setup":
            from kelan.setup import cmd_setup
            return cmd_setup(argv[1:])
        if cmd == "update":
            from kelan.intel.cli import cmd_update
            return cmd_update(argv[1:])
        if cmd == "export-bundle":
            from kelan.intel.cli import cmd_export_bundle
            return cmd_export_bundle(argv[1:])
        if cmd == "intel":
            from kelan.intel.cli import cmd_intel
            return cmd_intel(argv[1:])
        if cmd == "sca":
            sys.argv = ["kelan"] + [*argv[1:], "--only", "sca", "--show"]
            return _delegate() or 0
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
    finally:
        if dash_proc:
            _stop_dashboard_server(dash_proc)


if __name__ == "__main__":
    sys.exit(main())
