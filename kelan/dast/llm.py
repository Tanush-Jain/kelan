



from __future__ import annotations
import json
from typing import Optional

import httpx


CATEGORY_CWE = {
    "header": "CWE-693",
    "xss": "CWE-79",
    "sqli": "CWE-89",
    "cmdi": "CWE-78",
    "path_traversal": "CWE-22",
    "idor": "CWE-639",
    "ssrf": "CWE-918",
    "open_redirect": "CWE-601",
    "clickjacking": "CWE-1021",
    "ratelimit": "CWE-770",
}



REMEDIATION_TRUTH = {
    "header": "Add the missing security response header. Specifically ensure "
              "Content-Security-Policy (CSP), X-Frame-Options, "
              "X-Content-Type-Options, Referrer-Policy, Permissions-Policy and "
              "Strict-Transport-Security (HSTS) are present on all responses, "
              "especially HTML pages.",
    "xss": "Reflect user input only after proper output encoding for the context "
           "(HTML body vs attribute vs JavaScript). Validate/allowlist input and "
           "set a Content-Security-Policy.",
    "ratelimit": "Enforce rate limiting on a per-client basis that cannot be "
                 "bypassed by changing client-supplied headers like "
                 "X-Forwarded-For; bind the bucket to the source IP or a "
                 "cryptographically-derived client binding, keep the bucket "
                 "shared, and do not reset it on each request.",
}

LOCK = (
    "You are improving readability of a machine-verified security finding. "
    "You MUST obey these constraints:\n"
    "1. Keep the given category strictly. Do not switch categories.\n"
    "2. You may only rewrite the 'title', 'remediation', and 'cwe'. "
    "Never change 'severity', 'confidence', or 'evidence'.\n"
    "3. The category is {category}. The CWE must remain in "
    "[{allowed_cwes}]. Do not propose a vulnerability class "
    "other than {category} — for example, never mention SQL injection "
    "for a header or CSP finding.\n"
    "4. Base remediation only on the function's provided remediation.\n"
    "5. Return ONLY a JSON object: {{\"title\": str, \"remediation\": str, "
    "\"cwe\": str}}\n"
)


def _cwe_bucket(category: str) -> str:
    return CATEGORY_CWE.get(category, "CWE-710")


async def enrich_finding(finding: dict,
                         endpoint: str = "http://127.0.0.1:11434",
                         model: str = "qwen2.5-coder:latest") -> dict:


    out = dict(finding)
    category = finding.get("category", "header")
    allowed = _cwe_bucket(category)

    prompt = LOCK.format(category=category, allowed_cwes=allowed)
    user_msg = (
        f"category: {category}\n"
        f"deterministic title: {finding.get('title')}\n"
        f"detected remediation: {REMEDIATION_TRUTH.get(category, '')}\n"
        f"evidence: {json.dumps(finding.get('evidence', []))}\n"
        "Rewrite title and remediation, keep category and allowed CWE.\n"
    )
    payload = {
        "model": model, "stream": False, "format": "json",
        "messages": [
            {"role": "system", "content": prompt},
            {"role": "user", "content": user_msg},
        ],
    }
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(f"{endpoint.rstrip('/')}/api/chat", json=payload)
            r.raise_for_status()
            data = r.json()
            text = data.get("message", {}).get("content", "")
            content = json.loads(text)
    except (httpx.HTTPError, KeyError, json.JSONDecodeError, ValueError):
        return out



    new_cwe = str(content.get("cwe", allowed)).upper()
    if category == "header" and new_cwe not in ("CWE-693", "CWE-1004"):
        return out


    if not new_cwe.startswith("CWE-"):
        new_cwe = allowed

    out["title"] = str(content.get("title", finding.get("title")))[:160]
    out["remediation"] = str(content.get("remediation", out.get("remediation")))[:500]
    out["cwe"] = new_cwe
    return out
