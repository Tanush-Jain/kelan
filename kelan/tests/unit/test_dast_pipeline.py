from unittest import mock
import pytest
import httpx

from kelan.dast.heuristics import grade_idor, reflected, sql_error_hint, traversal_hit, ssti_hit
from kelan.dast.bypass import build_probes
from kelan.dast.report import Report, Finding
from kelan.dast.pipeline import _check_headers, _builtin_summary


def test_grade_idor_non_200():

    resp_a = mock.Mock(spec=httpx.Response)
    resp_b = mock.Mock(spec=httpx.Response)
    

    resp_a.status_code = 404
    resp_b.status_code = 404
    conf, note = grade_idor(resp_a, resp_b)
    assert conf == "none"
    assert "not evidence of IDOR" in note


    resp_a.status_code = 200
    resp_b.status_code = 404
    conf, note = grade_idor(resp_a, resp_b)
    assert conf == "none"
    assert "not evidence of IDOR" in note


def test_grade_idor_identical_200():
    resp_a = mock.Mock(spec=httpx.Response)
    resp_b = mock.Mock(spec=httpx.Response)
    
    resp_a.status_code = 200
    resp_b.status_code = 200
    resp_a.content = b"identical body content"
    resp_b.content = b"identical body content"
    resp_a.text = "identical body content"
    resp_b.text = "identical body content"
    
    conf, note = grade_idor(resp_a, resp_b)
    assert conf == "none"
    assert "identical responses" in note


def test_grade_idor_different_200():
    resp_a = mock.Mock(spec=httpx.Response)
    resp_b = mock.Mock(spec=httpx.Response)
    
    resp_a.status_code = 200
    resp_b.status_code = 200
    

    resp_a.content = b"User Profile: Alice"
    resp_b.content = b"User Profile: Bob, email: bob@example.com, secret: 12345"
    resp_a.text = "User Profile: Alice"
    resp_b.text = "User Profile: Bob, email: bob@example.com, secret: 12345"
    
    conf, note = grade_idor(resp_a, resp_b)
    assert conf == "strong"
    assert "responses differ across ids" in note
    

    resp_a.content = b"Welcome User" + b" " * 8
    resp_b.content = b"Welcome User"
    resp_a.text = "Welcome User"
    resp_b.text = "Welcome User"
    conf, note = grade_idor(resp_a, resp_b)
    assert conf == "weak"


def test_build_probes_no_bypass():
    probes = build_probes(("xss", "sqli"), bypass=False)

    for cat, name, payload in probes:
        assert name == "raw"


def test_build_probes_with_bypass():
    probes = build_probes(("xss",), bypass=True)

    variants = [p[1] for p in probes]
    assert "pct-lower" in variants
    assert "double-pct" in variants
    assert "comment-break" in variants


def test_check_headers():
    report = Report(target="http://example.com", model="dummy")
    resp_headers = {
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
    }
    

    _check_headers(resp_headers, report, "http://example.com")
    
    categories = [f.category for f in report.findings]
    assert "header" in categories
    assert len(report.findings) > 0

    h_titles = [f.title for f in report.findings]
    assert any("strict-transport-security" in t for t in h_titles)


def test_builtin_summary():
    report = Report(target="http://example.com", model="dummy")
    

    assert "No confirmed weaknesses" in _builtin_summary(report)
    

    f = Finding(
        url="http://example.com", method="GET", param="q", category="xss",
        title="Reflected XSS", evidence="reflected", severity="HIGH", cwe="CWE-79"
    )
    report.add(f)
    summary = _builtin_summary(report)
    assert "Top risks" in summary
    assert "HIGH" in summary
    assert "CWE-79" in summary
