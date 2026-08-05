"""Deterministic evidence graders — detection is never left to the LLM."""
from __future__ import annotations

import re

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

_DISCLOSURE_HEADERS = {
    "server": ("CWE-200", "LOW", "Server header discloses web server technology"),
    "x-powered-by": ("CWE-200", "LOW", "X-Powered-By header discloses backend framework"),
    "x-aspnet-version": ("CWE-200", "MEDIUM", "X-AspNet-Version discloses exact ASP.NET version"),
    "x-generator": ("CWE-200", "LOW", "X-Generator header discloses CMS/generator tool"),
}


def grade_headers(url: str, headers: dict) -> list[Finding]:
    """Check for missing security headers and technology disclosure headers."""
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

    for header, (cwe, sev, title) in _DISCLOSURE_HEADERS.items():
        if header in lower:
            val = lower[header][:120]
            findings.append(Finding(
                url=url, method="GET", param="-", category="header",
                cwe=cwe, severity=sev, title=title,
                evidence=f"{header}: {val}",
                remediation=f"Remove or obscure the '{header}' response header in production.",
                confidence="strong",
            ))

    return findings


def grade_sensitive_files(url: str, status: int, body: str) -> list[Finding]:
    """Check if common sensitive files or administrative endpoints are publicly exposed."""
    findings: list[Finding] = []
    if status != 200 or not body:
        return findings

    u = url.lower()
    if "/.git/head" in u and ("ref: refs/" in body or "master" in body or "main" in body):
        findings.append(Finding(
            url=url, method="GET", param="-", category="exposure",
            cwe="CWE-538", severity="CRITICAL",
            title="Exposed Git Repository (/.git/HEAD)",
            evidence=f"HTTP 200 response contains valid Git HEAD pointer: '{body[:60].strip()}'",
            remediation="Deny public HTTP access to .git directories in web server configuration.",
            confidence="strong",
        ))

    elif "/.env" in u and any(k in body for k in ("DB_PASSWORD", "SECRET_KEY", "AWS_ACCESS_KEY", "DATABASE_URL")):
        findings.append(Finding(
            url=url, method="GET", param="-", category="exposure",
            cwe="CWE-538", severity="CRITICAL",
            title="Exposed Environment File (/.env)",
            evidence="HTTP 200 response discloses sensitive environment variables / secret keys",
            remediation="Remove .env files from the web root and ensure web servers block dotfiles.",
            confidence="strong",
        ))

    elif any(p in u for p in ("/swagger.json", "/openapi.json")) and any(k in body for k in ("openapi", "swagger")):
        findings.append(Finding(
            url=url, method="GET", param="-", category="exposure",
            cwe="CWE-200", severity="MEDIUM",
            title="Public API Documentation Exposure",
            evidence="HTTP 200 response exposes full OpenAPI/Swagger definition schema",
            remediation="Restrict access to API documentation endpoints in production environments.",
            confidence="strong",
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
