from __future__ import annotations

import json
import os
from pathlib import Path
from unittest import mock

import pytest

from kelan.core.plugin import ScanConfig, ScanContext, ScanTarget, ScopeKind
from kelan.plugins.ports import PortsPlugin
from kelan.setup import (
    check_ollama_status,
    cmd_setup,
    get_platform_dirs,
    pull_ollama_model,
    run_setup,
    setup_scheduled_update_linux,
    setup_scheduled_update_macos,
    setup_scheduled_update_windows,
)


# ============================================================================
# 1. Platform Directories and Disk Space Checks
# ============================================================================

def test_get_platform_dirs():
    # Test Windows environment paths
    with mock.patch("platform.system", return_value="Windows"), \
         mock.patch.dict(os.environ, {"LOCALAPPDATA": "C:\\Users\\test\\AppData\\Local", "APPDATA": "C:\\Users\\test\\AppData\\Roaming"}):
        data_dir, config_dir = get_platform_dirs()
        assert "Local" in str(data_dir)
        assert "Roaming" in str(config_dir)

    # Test Linux environment paths
    with mock.patch("platform.system", return_value="Linux"), \
         mock.patch.dict(os.environ, {"XDG_DATA_HOME": "/home/test/.local/share", "XDG_CONFIG_HOME": "/home/test/.config"}):
        data_dir, config_dir = get_platform_dirs()
        assert "/home/test/.local/share/kelan" == str(data_dir)
        assert "/home/test/.config/kelan" == str(config_dir)

    # Test macOS environment paths
    with mock.patch("platform.system", return_value="Darwin"):
        data_dir, config_dir = get_platform_dirs()
        assert "Library/Application Support/kelan" in str(data_dir)


# ============================================================================
# 2. Ollama Detection & Model Pulling
# ============================================================================

@pytest.mark.asyncio
async def test_check_ollama_status_reachable():
    mock_resp_version = mock.MagicMock()
    mock_resp_version.status_code = 200
    mock_resp_version.json.return_value = {"version": "0.5.12"}

    mock_resp_tags = mock.MagicMock()
    mock_resp_tags.status_code = 200
    mock_resp_tags.json.return_value = {
        "models": [{"name": "qwen2.5-coder:latest"}, {"name": "gemma4:latest"}]
    }

    async def mock_get(url):
        if "version" in url:
            return mock_resp_version
        return mock_resp_tags

    with mock.patch("httpx.AsyncClient.get", side_effect=mock_get):
        ok, ver, models = await check_ollama_status()
        assert ok is True
        assert ver == "0.5.12"
        assert "qwen2.5-coder:latest" in models


@pytest.mark.asyncio
async def test_check_ollama_status_unreachable():
    with mock.patch("httpx.AsyncClient.get", side_effect=Exception("Connection refused")):
        ok, ver, models = await check_ollama_status()
        assert ok is False
        assert ver == ""
        assert models == []


@pytest.mark.asyncio
async def test_pull_ollama_model():
    # Mock streaming response
    class MockStreamResponse:
        status_code = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

        async def aiter_lines(self):
            yield json.dumps({"status": "pulling manifest"})
            yield json.dumps({"status": "downloading", "completed": 500, "total": 1000})
            yield json.dumps({"status": "success"})

    with mock.patch("httpx.AsyncClient.stream", return_value=MockStreamResponse()):
        ok = await pull_ollama_model("qwen2.5-coder:latest")
        assert ok is True


# ============================================================================
# 3. Scheduled Daily Update Handlers
# ============================================================================

def test_setup_scheduled_update_windows():
    mock_res = mock.MagicMock()
    mock_res.returncode = 0
    mock_res.stdout = "SUCCESS: The scheduled task 'KelanIntelUpdate' has successfully been created."

    with mock.patch("subprocess.run", return_value=mock_res) as mock_run:
        ok, msg = setup_scheduled_update_windows("C:\\Program Files\\Kelan\\kelan.exe")
        assert ok is True
        assert "KelanIntelUpdate" in msg
        mock_run.assert_called_once()
        cmd_args = mock_run.call_args[0][0]
        assert "schtasks" in cmd_args
        assert "/sc" in cmd_args
        assert "daily" in cmd_args


def test_setup_scheduled_update_linux(tmp_path):
    with mock.patch("pathlib.Path.home", return_value=tmp_path), \
         mock.patch("subprocess.run") as mock_run:
        ok, msg = setup_scheduled_update_linux("/usr/local/bin/kelan")
        assert ok is True
        assert "kelan-update.timer" in msg

        service_file = tmp_path / ".config" / "systemd" / "user" / "kelan-update.service"
        timer_file = tmp_path / ".config" / "systemd" / "user" / "kelan-update.timer"
        assert service_file.exists()
        assert timer_file.exists()
        assert "/usr/local/bin/kelan update" in service_file.read_text()


def test_setup_scheduled_update_macos(tmp_path):
    with mock.patch("pathlib.Path.home", return_value=tmp_path), \
         mock.patch("subprocess.run") as mock_run:
        ok, msg = setup_scheduled_update_macos("/usr/local/bin/kelan")
        assert ok is True
        assert "com.kelan.update" in msg

        plist_file = tmp_path / "Library" / "LaunchAgents" / "com.kelan.update.plist"
        assert plist_file.exists()
        assert "<string>update</string>" in plist_file.read_text()


# ============================================================================
# 4. End-to-End Non-Interactive `kelan setup`
# ============================================================================

@pytest.mark.asyncio
async def test_run_setup_non_interactive(tmp_path):
    with mock.patch("pathlib.Path.home", return_value=tmp_path), \
         mock.patch("kelan.setup.check_ollama_status", return_value=(True, "0.5.12", ["qwen2.5-coder:latest"])), \
         mock.patch("kelan.setup.IntelUpdater.update", return_value=[]), \
         mock.patch("kelan.setup.doctor", return_value=0):

        code = await run_setup(
            pull_model=False,
            schedule_daily=False,
            non_interactive=True,
            recommended_model="qwen2.5-coder:latest",
        )
        assert code == 0


def test_cmd_setup_cli(monkeypatch):
    with mock.patch("kelan.setup.run_setup", return_value=0) as mock_setup:
        ret = cmd_setup(["--yes", "--no-schedule"])
        assert ret == 0


# ============================================================================
# 5. Recon Ports Plugin Degradation
# ============================================================================

@pytest.mark.asyncio
async def test_recon_ports_degradation_without_extra(tmp_path):
    target = ScanTarget(ScopeKind.HOST, "127.0.0.1")
    ctx = ScanContext(target, ScanConfig(values={"recon_ports": {"mode": "syn"}}), tmp_path)

    plugin = PortsPlugin()

    # Simulate missing scapy / netifaces
    with mock.patch.dict("sys.modules", {"scapy": None, "netifaces": None}):
        res = await plugin.run(ctx)
        assert res.meta.get("recon_degraded") is True
        assert "Raw packet recon requires the [recon] extra" in res.errors[0]
        assert "pip install kelan[recon]" in res.errors[0]
        assert "Npcap" in res.errors[0]


# ============================================================================
# 6. Windows Packaging Files Integrity
# ============================================================================

def test_packaging_files_exist():
    root = Path(__file__).resolve().parent.parent.parent.parent
    assert (root / "kelan.spec").exists()
    assert (root / "packaging" / "windows" / "kelan.spec").exists()
    assert (root / "packaging" / "windows" / "installer.iss").exists()
    assert (root / "packaging" / "windows" / "install_notice.txt").exists()
    assert (root / "scripts" / "install.ps1").exists()
    assert (root / ".github" / "workflows" / "windows-release.yml").exists()
    assert (root / "docs" / "WINDOWS.md").exists()

    # Verify install.ps1 contains checksum verification and official repo URL
    ps1_content = (root / "scripts" / "install.ps1").read_text()
    assert "Tanush-Jain/kelan" in ps1_content
    assert "Get-FileHash" in ps1_content
    assert "SHA256SUMS.txt" in ps1_content
    assert "KelanSetup.exe" in ps1_content
    assert "iex" not in ps1_content.lower()

    # Verify Inno Setup installer has eBPF Linux-only notice and PATH integration
    iss_content = (root / "packaging" / "windows" / "installer.iss").read_text()
    assert "Kernel eBPF/XDP network enforcement is Linux-only" in (root / "packaging" / "windows" / "install_notice.txt").read_text()
    assert "ChangesEnvironment=yes" in iss_content
    assert "NeedsAddPath" in iss_content
