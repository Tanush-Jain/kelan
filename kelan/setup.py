from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, DownloadColumn, Progress, TextColumn, TimeRemainingColumn
from rich.prompt import Confirm

from kelan.doctor import doctor
from kelan.intel.db import IntelStore
from kelan.intel.updater import IntelUpdater


def get_platform_dirs() -> tuple[Path, Path]:
    """Returns standard platform (data_dir, config_dir)."""
    system = platform.system().lower()
    home = Path.home()

    if "windows" in system:
        local_app = os.environ.get("LOCALAPPDATA") or str(home / "AppData" / "Local")
        roaming_app = os.environ.get("APPDATA") or str(home / "AppData" / "Roaming")
        data_dir = Path(local_app) / "kelan"
        config_dir = Path(roaming_app) / "kelan"
    elif "darwin" in system:
        data_dir = home / "Library" / "Application Support" / "kelan"
        config_dir = data_dir
    else:  # Linux and POSIX
        data_home = os.environ.get("XDG_DATA_HOME") or str(home / ".local" / "share")
        config_home = os.environ.get("XDG_CONFIG_HOME") or str(home / ".config")
        data_dir = Path(data_home) / "kelan"
        config_dir = Path(config_home) / "kelan"

    return data_dir, config_dir


async def check_ollama_status(endpoint: str = "http://127.0.0.1:11434") -> tuple[bool, str, list[str]]:
    """Checks if Ollama is running, returns (is_running, version, installed_models)."""
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            version_resp = await client.get(f"{endpoint}/api/version")
            version_str = "unknown"
            if version_resp.status_code == 200:
                version_str = version_resp.json().get("version", "unknown")

            tags_resp = await client.get(f"{endpoint}/api/tags")
            models = []
            if tags_resp.status_code == 200:
                data = tags_resp.json()
                models = [m.get("name", "") for m in data.get("models", []) if m.get("name")]

            return True, version_str, models
    except Exception:
        return False, "", []


async def pull_ollama_model(model_name: str, endpoint: str = "http://127.0.0.1:11434", console: Console | None = None) -> bool:
    """Pulls a model from Ollama API with progress reporting."""
    c = console or Console()
    url = f"{endpoint}/api/pull"

    c.print(f"[bold cyan]Pulling recommended model:[/bold cyan] {model_name}...")
    try:
        async with (
            httpx.AsyncClient(timeout=httpx.Timeout(600.0, connect=10.0)) as client,
            client.stream("POST", url, json={"name": model_name, "stream": True}) as response,
        ):
                if response.status_code != 200:
                    c.print(f"[bold red]Failed to initiate pull:[/bold red] HTTP {response.status_code}")
                    return False

                with Progress(
                    TextColumn("[bold blue]{task.description}"),
                    BarColumn(),
                    DownloadColumn(),
                    TimeRemainingColumn(),
                    console=c,
                ) as progress:
                    task = progress.add_task("Downloading", total=100)

                    async for line in response.aiter_lines():
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                            status = data.get("status", "")
                            total = data.get("total", 0)
                            completed = data.get("completed", 0)

                            if total > 0:
                                progress.update(task, description=status, total=total, completed=completed)
                            else:
                                progress.update(task, description=status)
                        except json.JSONDecodeError:
                            continue

        c.print(f"[bold green]✔ Model '{model_name}' successfully pulled![/bold green]")
        return True
    except Exception as exc:
        c.print(f"[bold red]Error pulling model '{model_name}':[/bold red] {exc}")
        return False


def setup_scheduled_update_windows(kelan_bin: str) -> tuple[bool, str]:
    """Configures daily update via Windows Task Scheduler."""
    task_name = "KelanIntelUpdate"
    cmd = [
        "schtasks",
        "/create",
        "/tn",
        task_name,
        "/tr",
        f'"{kelan_bin}" update',
        "/sc",
        "daily",
        "/st",
        "03:00",
        "/f",
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if res.returncode == 0:
            return True, f"Windows Task Scheduler task '{task_name}' created (daily at 03:00)."
        return False, res.stderr or res.stdout
    except Exception as exc:
        return False, str(exc)


def setup_scheduled_update_linux(kelan_bin: str) -> tuple[bool, str]:
    """Configures daily update via systemd user timer."""
    home = Path.home()
    systemd_user_dir = home / ".config" / "systemd" / "user"
    systemd_user_dir.mkdir(parents=True, exist_ok=True)

    service_file = systemd_user_dir / "kelan-update.service"
    timer_file = systemd_user_dir / "kelan-update.timer"

    service_content = f"""[Unit]
Description=Kelan Vulnerability Intelligence Daily Update

[Service]
Type=oneshot
ExecStart={kelan_bin} update
"""

    timer_content = """[Unit]
Description=Run Kelan update daily

[Timer]
OnCalendar=*-*-* 03:00:00
Persistent=true

[Install]
WantedBy=timers.target
"""
    try:
        service_file.write_text(service_content, encoding="utf-8")
        timer_file.write_text(timer_content, encoding="utf-8")
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
        subprocess.run(["systemctl", "--user", "enable", "--now", "kelan-update.timer"], check=False)
        return True, "systemd user timer 'kelan-update.timer' created and activated."
    except Exception as exc:
        return False, str(exc)


def setup_scheduled_update_macos(kelan_bin: str) -> tuple[bool, str]:
    """Configures daily update via launchd plist."""
    home = Path.home()
    agents_dir = home / "Library" / "LaunchAgents"
    agents_dir.mkdir(parents=True, exist_ok=True)
    plist_file = agents_dir / "com.kelan.update.plist"

    plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.kelan.update</string>
    <key>ProgramArguments</key>
    <array>
        <string>{kelan_bin}</string>
        <string>update</string>
    </array>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key>
        <integer>3</integer>
        <key>Minute</key>
        <integer>0</integer>
    </dict>
</dict>
</plist>
"""
    try:
        plist_file.write_text(plist_content, encoding="utf-8")
        subprocess.run(["launchctl", "unload", str(plist_file)], check=False, capture_output=True)
        subprocess.run(["launchctl", "load", str(plist_file)], check=False)
        return True, "launchd agent 'com.kelan.update' registered (daily at 03:00)."
    except Exception as exc:
        return False, str(exc)


async def run_setup(
    pull_model: bool | None = None,
    schedule_daily: bool | None = None,
    non_interactive: bool = False,
    recommended_model: str = "qwen2.5-coder:latest",
    console: Console | None = None,
) -> int:
    c = console or Console()

    c.print(Panel.fit(
        "[bold cyan]Kelan Community Setup[/bold cyan]\n"
        "[dim]Configures platform storage, local LLM inference, vulnerability intelligence, and readiness checks.[/dim]"
    ))

    # 1. OS & Architecture Check
    sys_name = platform.system()
    machine = platform.machine()
    release = platform.release()

    is_windows = sys_name.lower().startswith("win")
    c.print("\n[bold]1. Operating System & Platform[/bold]")
    if is_windows:
        c.print(f"  [green]✔[/green] Windows {release} ({machine}) detected.")
        c.print("  [dim]Note: Kernel eBPF/XDP network enforcement is Linux-only. On Windows, Kelan operates in audit, SAST, DAST, and SCA mode.[/dim]")
    else:
        c.print(f"  [green]✔[/green] {sys_name} {release} ({machine}) detected.")

    # 2. Disk Space Check
    c.print("\n[bold]2. Disk Space Verification[/bold]")
    try:
        total_b, used_b, free_b = shutil.disk_usage(Path.home())
        free_gb = free_b / (1024 ** 3)
        if free_gb >= 5.0:
            c.print(f"  [green]✔ Free disk space:[/green] {free_gb:.1f} GB available (>= 5.0 GB recommended for models & feeds).")
        else:
            c.print(f"  [yellow]▲ Free disk space:[/yellow] {free_gb:.1f} GB available (recommend >= 5.0 GB for model weights).")
    except Exception as exc:
        c.print(f"  [yellow]▲ Could not determine disk usage:[/yellow] {exc}")

    # 3. Detect Ollama
    c.print("\n[bold]3. Ollama Service Detection[/bold]")
    ollama_ok, ollama_ver, installed_models = await check_ollama_status()
    if ollama_ok:
        c.print(f"  [green]✔ Ollama v{ollama_ver}[/green] is running at http://127.0.0.1:11434.")
        if installed_models:
            c.print(f"  [dim]Installed models:[/dim] {', '.join(installed_models[:5])}")
    else:
        c.print("  [yellow]▲ Ollama is not currently reachable at http://127.0.0.1:11434[/yellow]")
        c.print("  [bold]Install Ollama to enable AI static analysis & dynamic probing:[/bold]")
        if is_windows:
            c.print("    Download installer: [cyan]https://ollama.com/download/OllamaSetup.exe[/cyan]")
        elif "darwin" in sys_name.lower():
            c.print("    Download Ollama for macOS: [cyan]https://ollama.com/download[/cyan]")
        else:
            c.print("    Install script: [cyan]curl -fsSL https://ollama.com/install.sh | sh[/cyan]")
        c.print("    After installation, run: [dim]ollama serve[/dim]\n")

    # 4. Model Selection & Pull
    if ollama_ok:
        c.print("\n[bold]4. Recommended LLM Model[/bold]")
        has_model = any(recommended_model in m for m in installed_models)
        if has_model:
            c.print(f"  [green]✔ Recommended model '{recommended_model}' is already installed.[/green]")
        else:
            should_pull = False
            if pull_model is True:
                should_pull = True
            elif pull_model is False or non_interactive:
                should_pull = False
            else:
                try:
                    should_pull = Confirm.ask(f"  Pull recommended model '{recommended_model}' now?", default=True)
                except Exception:
                    should_pull = False

            if should_pull:
                await pull_ollama_model(recommended_model, console=c)
            else:
                c.print(f"  [dim]Skipped. You can pull the model manually later using: ollama pull {recommended_model}[/dim]")

    # 5. Standard Directories & Initial Config
    c.print("\n[bold]5. Standard Directories & Local Storage[/bold]")
    data_dir, config_dir = get_platform_dirs()
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        config_dir.mkdir(parents=True, exist_ok=True)
        config_file = config_dir / "config.toml"
        if not config_file.exists():
            cfg_body = f"""# Kelan Configuration File
[intel]
db_path = "{data_dir / 'intel.db'}"
max_age_days = 7

[ollama]
endpoint = "http://127.0.0.1:11434"
model = "{recommended_model}"
"""
            config_file.write_text(cfg_body, encoding="utf-8")
        c.print(f"  [green]✔ Data directory:[/green]   {data_dir}")
        c.print(f"  [green]✔ Config directory:[/green] {config_dir}")
    except Exception as exc:
        c.print(f"  [red]✘ Directory creation error:[/red] {exc}")

    # 6. Initial Vulnerability Intelligence Sync
    c.print("\n[bold]6. Initial Vulnerability Intelligence Sync[/bold]")
    intel_db_path = data_dir / "intel.db"
    store = IntelStore(intel_db_path)
    updater = IntelUpdater(store=store)
    try:
        c.print("  [cyan]Running initial feed update (CISA KEV, EPSS, OSV, GHSA, NVD)...[/cyan]")
        await updater.update(console=c)
    finally:
        store.close()

    # 7. Scheduled Daily Update (Offers, Never Forces)
    c.print("\n[bold]7. Automatic Daily Intelligence Update[/bold]")
    should_schedule = False
    if schedule_daily is True:
        should_schedule = True
    elif schedule_daily is False or non_interactive:
        should_schedule = False
    else:
        try:
            should_schedule = Confirm.ask(
                "  Configure an automatic daily update task for vulnerability intelligence (runs daily at 03:00)?",
                default=False,
            )
        except Exception:
            should_schedule = False

    if should_schedule:
        kelan_exe = shutil.which("kelan") or sys.executable
        if is_windows:
            ok, msg = setup_scheduled_update_windows(kelan_exe)
        elif "darwin" in sys_name.lower():
            ok, msg = setup_scheduled_update_macos(kelan_exe)
        else:
            ok, msg = setup_scheduled_update_linux(kelan_exe)

        if ok:
            c.print(f"  [green]✔ {msg}[/green]")
        else:
            c.print(f"  [yellow]▲ Could not register schedule: {msg}[/yellow]")
    else:
        c.print("  [dim]Skipped. Automatic update was not scheduled. You can sync anytime with 'kelan update'.[/dim]")

    # 8. Readiness Doctor & Checklist
    c.print("\n[bold]8. System Readiness Verification[/bold]")
    doc_code = await doctor()

    c.print("\n" + "=" * 60)
    if doc_code == 0:
        c.print("[bold green]✔ Kelan setup complete! Your environment is ready to scan.[/bold green]")
        c.print("  Try running your first scan:\n    [cyan]kelan run . --show[/cyan]")
    else:
        c.print("[bold yellow]▲ Setup finished with warnings. Review the checklist items above.[/bold yellow]")
    c.print("=" * 60 + "\n")

    return doc_code


def cmd_setup(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="kelan setup",
        description="Automated initial configuration of Kelan on Windows, macOS, or Linux.",
    )
    parser.add_argument("--yes", "-y", action="store_true", help="Non-interactive setup with defaults")
    parser.add_argument("--pull-model", action="store_true", default=None, help="Pull recommended Ollama model")
    parser.add_argument("--no-pull-model", action="store_false", dest="pull_model", help="Do not pull Ollama model")
    parser.add_argument("--schedule", action="store_true", default=None, help="Register daily scheduled update")
    parser.add_argument("--no-schedule", action="store_false", dest="schedule_daily", help="Do not register scheduled update")
    parser.add_argument("--model", default="qwen2.5-coder:latest", help="Ollama model to recommend (default: qwen2.5-coder:latest)")

    args = parser.parse_args(argv)

    return asyncio.run(
        run_setup(
            pull_model=args.pull_model,
            schedule_daily=args.schedule_daily,
            non_interactive=args.yes,
            recommended_model=args.model,
        )
    )

