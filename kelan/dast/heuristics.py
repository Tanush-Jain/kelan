
from __future__ import annotations

import re

SQL_ERROR_HINTS = re.compile(
    r"(sqlsyntax|syntax error|unclosed quotation|incorrect syntax|"
    r"you have an error in your sql|mysql_fetch|ora-\d{5}|"
    r"microsoft ole db|postgresql|sqlite3\.(operational|error)|"
    r"pg_query|exception.*jdbc|invalid query)", re.I
)


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


def grade_ratelimit_burst(responses: list[dict]) -> Optional[Finding]:



    from typing import Optional
    from kelan.dast.report import Finding
    
    if len(responses) < 2:
        return None
    baseline_429 = sum(1 for r in responses if r.get("code") == 429)
    if baseline_429 == 0:
        return None
    

    for r in responses:
        if r.get("code") != 429 and r.get("identity") != "baseline":
            f = Finding(
                url=r.get("url", ""), method="GET", param="X-Forwarded-For",
                category="ratelimit",
                title="Rate limit bypassable via client-supplied identity header",
                evidence=f"baseline hit 429 but identity={r.get('identity')} did not; quota evadable",
                severity="HIGH",
                confidence="strong", cwe="CWE-770",
                remediation="Bind the rate-limit bucket to the trusted source "
                            "IP, not to X-Forwarded-For / X-Real-IP.",
            )
            return f
    return None

