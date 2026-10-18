import pytest
import tempfile
from pathlib import Path

from kelan.core.finding import Severity
from kelan.analyze.ratelimit import audit_codebase, _tagged_usages
from kelan.dast.heuristics import grade_ratelimit_burst
from kelan.run import detect_scope, ScopeKind


def test_static_ratelimit_analysis():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        

        f1 = tmp_path / "server.py"
        f1.write_text("""
        def handle_request(req):
            ip = req.headers.get("X-Forwarded-For")
            now = time.time()
            return "OK"
        """)
        

        f2 = tmp_path / "limiter.py"
        f2.write_text("""
        limiter = RateLimiter(capacity=10)
        key = make_key(userId)
        """)
        

        f3 = tmp_path / "bad_handler.py"
        f3.write_text("""
        def process(req):
            rl = RateLimiter(capacity=5)
            rl = RateLimiter(capacity=5)
        """)
        
        findings = audit_codebase(tmp_dir)
        

        categories = [f.title for f in findings]
        assert any("Client identity trusts spoofable X-Forwarded-For" in c for c in categories)
        assert any("Rate-limit refill uses wall clock" in c for c in categories)
        assert any("Rate-limit key is client-controlled" in c for c in categories)
        assert any("Rate-limit bucket/key initialized per request" in c for c in categories)


def test_grade_ratelimit_burst():

    res_a = [
        {"code": 200, "identity": "baseline", "url": "http://target/"},
        {"code": 200, "identity": "1.1.1.1", "url": "http://target/"}
    ]
    assert grade_ratelimit_burst(res_a) is None
    

    res_b = [
        {"code": 429, "identity": "baseline", "url": "http://target/"},
        {"code": 200, "identity": "1.2.3.4", "url": "http://target/"}
    ]
    finding = grade_ratelimit_burst(res_b)
    assert finding is not None
    assert finding.category == "ratelimit"
    assert finding.severity == "HIGH"
    assert "quota evadable" in finding.evidence


def test_cli_target_scope_detection():
    assert detect_scope("http://localhost:8080") == ScopeKind.URL
    assert detect_scope("https://github.com/org/repo.git") == ScopeKind.REPO
    assert detect_scope("git@github.com:org/repo") == ScopeKind.REPO
    assert detect_scope(".") == ScopeKind.CODEBASE
    assert detect_scope("scanme.nmap.org") == ScopeKind.HOST
