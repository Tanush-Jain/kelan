"""Deterministic evidence graders — detection is never left to the LLM."""
from __future__ import annotations

import re
from typing import Optional

from kelan.dast.report import Finding

SQL_ERROR_HINTS = re.compile(
    r"(sqlsyntax|syntax error|unclosed quotation|incorrect syntax|"
    r"you have an error in your sql|mysql_fetch|ora-\d{5}|"
    r"microsoft ole db|postgresql|sqlite3\.(operational|error)|"
    r"pg_query|exception.*jdbc|invalid query)", re.I
)

REQUIRED_HEADERS: dict[str, dict] = {
    "content-security-policy": {
        "cwe_id": "CWE-693", "severity": "MEDIUM",
        "title": "Missing Content-Security-Policy header",
        "remediation": "Add a strict CSP header.",
    },
    "x-frame-options": {
        "cwe_id": "CWE-1021", "severity": "MEDIUM",
        "title": "Missing X-Frame-Options header (clickjacking)",
        "remediation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'.",
    },
    "x-content-type-options": {
        "cwe_id": "CWE-116", "severity": "LOW",
        "title": "Missing X-Content-Type-Options header (MIME sniffing)",
        "remediation": "Add 'X-Content-Type-Options: nosniff'.",
    },
    "referrer-policy": {
        "cwe_id": "CWE-116", "severity": "LOW",
        "title": "Missing Referrer-Policy header",
        "remediation": "Add 'Referrer-Policy: no-referrer' or 'strict-origin'.",
    },
    "permissions-policy": {
        "cwe_id": "CWE-693", "severity": "LOW",
        "title": "Missing Permissions-Policy header",
        "remediation": "Add 'Permissions-Policy: geolocation=(), microphone=()'.",
    },
    "strict-transport-security": {
        "cwe_id": "CWE-319", "severity": "MEDIUM",
        "title": "Missing Strict-Transport-Security header (HSTS)",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
    },
}


def grade_headers(url: str, headers: dict) -> list[Finding]:
    """Check for missing security headers."""
    findings: list[Finding] = []
    lower = {k.lower(): v for k, v in headers.items()}
    for header, meta in REQUIRED_HEADERS.items():
        if header not in lower:
            findings.append(Finding(
                url=url, method="GET", param="-", category="header",
                cwe=meta["cwe_id"], severity=meta["severity"],
                title=meta["title"],
                evidence=f"Header '{header}' absent from response",
                remediation=meta["remediation"], confidence="strong",
            ))
    return findings


def reflected(body: str, payload: str) -> bool:
    return bool(payload) and payload in body


def sql_error_hint(body: str) -> bool:
    return bool(SQL_ERROR_HINTS.search(body))


def traversal_hit(body: str) -> bool:
    return any(m in body for m in ("root:", "daemon:", "nobody:"))


def ssti_hit(body: str, oracle: str) -> bool:
    if oracle in ("{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"):
        return re.search(r"\b49\b", body) is not None
    return False


def grade_idor(resp_a, resp_b) -> tuple[str, str]:
    """Return (confidence, note). 404s are NOT IDOR evidence."""
    sa, sb = resp_a.status_code, resp_b.status_code
    if sa != 200 or sb != 200:
        return ("none",
                f"HTTP {sa}/{sb} for both ids — route likely missing or auth-gated; "
                f"not evidence of IDOR")
    len_a, len_b = len(resp_a.content), len(resp_b.content)
    if resp_a.text == resp_b.text and abs(len_a - len_b) < 8:
        return ("none", "identical responses for both ids")
    diff = abs(len_a - len_b)
    if diff > 40 or resp_a.text != resp_b.text:
        return ("strong", f"200 responses differ across ids (Δ{diff}B)")
    return ("weak", f"responses differ slightly (Δ{diff}B)")
