












from __future__ import annotations

import re
from pathlib import Path

from kelan.core.finding import Confidence, Finding, Severity

_BUCKET_RESET = re.compile(r"token_bucket\s*(\.\w+)?\s*=|Bucket\(|new\s+Limiter|RateLimiter\(", re.IGNORECASE)
_WALL_CLOCK = re.compile(r"time\.now|time\.time\(\)|datetime\.now|System\.currentTimeMillis", re.IGNORECASE)
_MONOTONIC_OK = re.compile(r"time\.monotonic|Stopwatch\.getTimestamp\(\)", re.IGNORECASE)
_FORWARDED = re.compile(r"X-Forwarded-For|X-Real-IP|cf-connecting-ip|remote_addr\s*=\s*.*headers", re.IGNORECASE)
_CLIENT_KEY = re.compile(r"key\s*=\s*\w+(userId|username|id|client)|make_key\(|key_func\(", re.IGNORECASE)


def _tagged_usages(path: Path) -> list[tuple[int, str, str]]:

    hits: list[tuple[int, str, str]] = []
    try:
        lines = path.read_text(errors="ignore").splitlines()
    except OSError:
        return hits
    locally_init = 0
    for i, ln in enumerate(lines, 1):
        low = ln.lower()
        if _WALL_CLOCK.search(ln) and not _MONOTONIC_OK.search(ln):
            hits.append((i, "wall_clock", ln.strip()))
        if _FORWARDED.search(low):
            hits.append((i, "trusted_forwarded", ln.strip()))
        if _CLIENT_KEY.search(low):
            hits.append((i, "client_key", ln.strip()))
        if _BUCKET_RESET.search(ln):
            locally_init += 1
            if locally_init > 1:
                hits.append((i, "bucket_per_request", ln.strip()))
    return hits


def audit_codebase(root: str | Path) -> list[Finding]:
    root = Path(root)
    findings: list[Finding] = []
    skip = {".git", "node_modules", "venv", ".venv", "target", "__pycache__"}
    patterns = ("*.py", "*.js", "*.ts", "*.go", "*.rb", "*.java")
    for p in root.rglob("*"):
        if not p.is_file() or any(part in skip for part in p.parts):
            continue
        if not any(p.match(pat) for pat in patterns):
            continue
        hits = _tagged_usages(p)
        for line_no, cat, snippet in hits:
            f = Finding(
                plugin="analyze_ratelimit", category="ratelimit",
                severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                cwe="CWE-770",
                title=_title_for(cat),
                remediation=_remediation_for(cat),
                location=f"{p}:{line_no}",
                target=str(root),
            )
            f.add_evidence("advisory", _desc_for(cat), ref=f"{p}:{line_no}",
                           snippet=snippet)
            findings.append(f)
    return findings


def _title_for(cat: str) -> str:
    return {
        "wall_clock": "Rate-limit refill uses wall clock (jumpable)",
        "trusted_forwarded": "Client identity trusts spoofable X-Forwarded-For",
        "client_key": "Rate-limit key is client-controlled",
        "bucket_per_request": "Rate-limit bucket/key initialized per request",
    }[cat]


def _remediation_for(cat: str) -> str:
    return {
        "wall_clock": "Use a monotonic clock (time.monotonic / System.nanoTime) "
                      "so refill cannot be accelerated by changing the system time.",
        "trusted_forwarded": "Derive client identity from the trusted source IP "
                             "or a mutually-authenticated binding; validate "
                             "X-Forwarded-For only against an approved proxy list.",
        "client_key": "Bind the bucket to an identity you trust server-side, "
                      "never to a value the client supplies directly.",
        "bucket_per_request": "Allocate/share the bucket per client (keyed by "
                              "trusted identity), never per request.",
    }[cat]


def _desc_for(cat: str) -> str:
    return {
        "wall_clock": "Refill condition compared to time.now; attacker or NTP "
                      "can shift the window.",
        "trusted_forwarded": "X-Forwarded-For is trusted for identity; a client "
                             "can rotate the header to reset its quota.",
        "client_key": "The rate-limit key derives from client input, letting an "
                      "attacker mint unlimited buckets.",
        "bucket_per_request": "A new bucket is created per request, so the "
                             "limiter never accumulates — quota never binds.",
    }[cat]
