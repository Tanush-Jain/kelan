import pytest
from unittest.mock import patch

from kelan.core.plugin import ScanConfig, ScanContext, ScanTarget, ScopeKind
from kelan.plugins.sast_adapter import SastPlugin
from kelan.scanner.analyzer import VulnerabilityAnalyzer, deterministic_scan_chunk


def test_deterministic_sqli_detection():
    chunk = {
        "file_path": "app/db.py",
        "content": 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        "start_line": 10,
    }
    findings = deterministic_scan_chunk(chunk)
    assert len(findings) == 1
    assert findings[0]["cwe_id"] == "CWE-89"
    assert findings[0]["severity"] == "CRITICAL"


def test_deterministic_cmdi_detection():
    chunk = {
        "file_path": "app/cmd.py",
        "content": 'subprocess.Popen("ls -la " + path, shell=True)',
        "start_line": 5,
    }
    findings = deterministic_scan_chunk(chunk)
    assert len(findings) == 1
    assert findings[0]["cwe_id"] == "CWE-78"
    assert findings[0]["severity"] == "HIGH"


def test_deterministic_clean_code():
    chunk = {
        "file_path": "app/clean.py",
        "content": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        "start_line": 1,
    }
    findings = deterministic_scan_chunk(chunk)
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_analyzer_ollama_offline_returns_deterministic_flaws():
    analyzer = VulnerabilityAnalyzer(endpoint="http://127.0.0.1:99999", timeout=0.1)
    chunk = {
        "file_path": "app/db.py",
        "content": 'cursor.execute(f"SELECT * FROM accounts WHERE acc = {acc_num}")',
        "start_line": 1,
    }
    with patch("kelan.ai.ollama_client.OllamaClient.generate_json", side_effect=Exception("Connection refused")):
        res = await analyzer.analyze_chunk(chunk)
        assert res["has_security_flaw"] is True
        assert res["llm_offline"] is True
        assert len(res["findings"]) == 1
        assert res["findings"][0]["cwe_id"] == "CWE-89"


@pytest.mark.asyncio
async def test_sast_plugin_detects_sqli_when_ollama_offline(tmp_path):
    vuln_file = tmp_path / "vulnerable.py"
    vuln_file.write_text('def search(user_input):\n    cursor.execute(f"SELECT * FROM users WHERE name = \'{user_input}\'")\n')

    target = ScanTarget(ScopeKind.CODEBASE, str(tmp_path))
    ctx = ScanContext(target, ScanConfig(), tmp_path)

    plugin = SastPlugin()
    with patch("kelan.ai.ollama_client.OllamaClient.generate_json", side_effect=Exception("Connection refused")):
        res = await plugin.run(ctx)
        assert len(res.findings) >= 1
        assert any(f.cwe == "CWE-89" for f in res.findings)
        assert res.meta.get("llm_status") == "offline (deterministic fallback active)"
        assert any("Ollama LLM was unreachable" in err for err in res.errors)

