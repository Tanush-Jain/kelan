# ══ Unit Tests: Kelan SAST 3-Layer Engine ═════════════════════════════════════
import pytest
from kelan.sast.engine import SastEngine
from kelan.sast.reachability import ReachabilityVerdict
from kelan.sast.rules.base import RuleConfidence
from kelan.sast.triage import DEFAULT_SAST_MODEL


@pytest.mark.asyncio
async def test_sast_regression_sqli_and_cmdi_offline():
    """Verify that with Ollama offline, both SQL injection and subprocess shell=True are detected deterministically."""
    code = """
import subprocess

def handle_request(user_input, cmd):
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor.execute(query)
    subprocess.call(cmd, shell=True)
"""
    engine = SastEngine()
    findings = await engine.scan_code("sample.py", code, use_reachability=False, use_llm=False)

    cwes = {f.cwe for f in findings}
    assert "CWE-89" in cwes, "SQL Injection (CWE-89) must be detected deterministically"
    assert "CWE-78" in cwes, "Command Injection (CWE-78) must be detected deterministically"

    for f in findings:
        assert f.confidence == RuleConfidence.HIGH
        assert len(f.source_to_sink_evidence) > 0


@pytest.mark.asyncio
async def test_sast_reachability_paths_and_verdicts():
    code = """
import subprocess

@app.get('/search')
def search_handler(user_input):
    return run_query(user_input)

def run_query(query_str):
    sql = f"SELECT * FROM data WHERE q = '{query_str}'"
    cursor.execute(sql)

def dead_function(cmd):
    subprocess.call(cmd, shell=True)

if __name__ == '__main__':
    search_handler('test')
"""
    engine = SastEngine()
    findings = await engine.scan_code("app.py", code, use_reachability=True, use_llm=False)

    sqli = next(f for f in findings if f.cwe == "CWE-89")
    cmdi = next(f for f in findings if f.cwe == "CWE-78")

    assert sqli.reachability_verdict == ReachabilityVerdict.REACHABLE.value
    assert sqli.reachability_path == ["search_handler", "run_query"]

    assert cmdi.reachability_verdict == ReachabilityVerdict.UNREACHABLE.value
    assert cmdi.reachability_path == []


@pytest.mark.asyncio
async def test_sast_reachability_unknown_never_rounded():
    """Verify that when dynamic dispatch is present, reachability is strictly unknown and not rounded up or down."""
    code = """
import subprocess

def dynamic_router(action, payload):
    fn = getattr(handlers, action)
    fn(payload)

def worker(cmd):
    subprocess.call(cmd, shell=True)
"""
    engine = SastEngine()
    findings = await engine.scan_code("module.py", code, use_reachability=True, use_llm=False)

    cmdi = next(f for f in findings if f.cwe == "CWE-78")
    assert cmdi.reachability_verdict == ReachabilityVerdict.UNKNOWN.value, "Unknown must stay unknown"
    assert cmdi.reachability_path == []


@pytest.mark.asyncio
async def test_llm_triage_skips_unreachable():
    """Verify that LLM triage is only invoked for reachable or unknown findings, skipping unreachable ones."""
    engine = SastEngine()
    code = """
import subprocess

def dead_function(cmd):
    subprocess.call(cmd, shell=True)

if __name__ == '__main__':
    pass
"""
    findings = await engine.scan_code("app.py", code, use_reachability=True, use_llm=True)
    assert len(findings) == 1
    f = findings[0]
    assert f.reachability_verdict == ReachabilityVerdict.UNREACHABLE.value
    assert f.llm_triage.get("status") == "skipped_unreachable"


def test_model_agnostic_default_and_override():
    engine = SastEngine(model="custom-model:latest")
    assert engine.model == "custom-model:latest"
    assert engine.triage_engine.model == "custom-model:latest"

    engine_default = SastEngine()
    assert engine_default.model == DEFAULT_SAST_MODEL
