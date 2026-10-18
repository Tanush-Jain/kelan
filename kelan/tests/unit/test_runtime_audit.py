import tempfile
from pathlib import Path
import pytest

from kelan.analyze.runtime import (
    _extract_re_patterns, is_redos_candidate, _validate_redos, audit_codebase
)

def test_extract_re_patterns():
    code = """
import re
re.compile(r"([a-zA-Z]+)*")
re.search("([0-9]+)+", data)
re.match(x, data) # dynamic pattern, should be skipped
"""
    patterns = _extract_re_patterns(code)
    assert len(patterns) == 2
    assert patterns[0][1] == r"([a-zA-Z]+)*"
    assert patterns[1][1] == r"([0-9]+)+"

def test_is_redos_candidate():
    assert is_redos_candidate(r"([a-zA-Z]+)*") is True
    assert is_redos_candidate(r"(a|b)+") is True
    assert is_redos_candidate(r"[a-z]+") is False

def test_validate_redos():

    assert _validate_redos(r"(a+)+$") is True

    assert _validate_redos(r"[a-z]+") is False

def test_audit_codebase_unbounded_loops_and_sinks():
    code = """
def test_func():
    items = []
    while True:
        items.append(1) # unbounded loop append
        
def safe_func():
    items = []
    for i in range(10):
        items.append(i) # bounded (has range limit)
        
def dangerous_sinks(x):
    eval(x) # dynamic eval
    import os
    os.system("ls")
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir) / "vuln.py"
        p.write_text(code)
        
        findings = audit_codebase(tmpdir, validate_redos=False)
        
        titles = [f.title for f in findings]
        assert "Unbounded collection/string growth in loop" in titles
        assert "Dynamic code execution (eval/exec)" in titles
        assert "os.system shell execution" in titles
