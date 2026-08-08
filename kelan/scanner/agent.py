















import argparse
import asyncio
import json
import sys
import urllib.parse

import httpx
import structlog

log = structlog.get_logger()

DEFAULT_MODEL    = "qwen2.5-coder:latest"
DEFAULT_ENDPOINT = "http://localhost:11434"
DOM_PREVIEW_LEN  = 1500

DAST_SYSTEM_PROMPT = """\
You are a dynamic application security (DAST) agent.
Analyze the provided HTTP response — its status code, headers, and HTML body —
for security misconfigurations and active attack surface vectors.

Focus on:
- Missing or weak security headers (CSP, X-Frame-Options, X-Content-Type-Options,
  Referrer-Policy, HSTS, Permissions-Policy)
- Unprotected HTML input fields and reflected URL parameters (XSS vectors)
- Unauthenticated API endpoints that expose user or admin data (BOLA/IDOR)
- Information disclosure in error messages or headers

Rules:
- Only report findings you can directly support with evidence from the provided data.
- Set "has_finding" to false if the response is clean.

Return ONLY a single valid JSON object matching this exact schema — no markdown, no prose:
{
  "has_finding": true,
  "missing_headers": ["<header-name>"],
  "attack_surface": ["<description of each discovered form / parameter / endpoint>"],
  "findings": [
    {
      "cwe_id": "<e.g. CWE-79>",
      "severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
      "title": "<concise title>",
      "evidence": "<exact header name or DOM snippet that proves the flaw>",
      "remediation": "<specific fix>"
    }
  ],
  "risk_summary": "<2-3 sentence overall risk assessment>"
}
"""

EXPECTED_SECURITY_HEADERS = [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "strict-transport-security",
]

PROBE_PAYLOADS = [
    "/?search=<script>alert(1)</script>",
    "/api/user?id=1",
    "/api/user?id=99",
]


async def _fetch(client: httpx.AsyncClient, url: str) -> httpx.Response | None:
    try:
        resp = await client.get(url, follow_redirects=True, timeout=10.0)
        log.info("dast_fetch", url=url, status=resp.status_code)
        return resp
    except Exception as exc:
        log.warning("dast_fetch_failed", url=url, error=str(exc))
        return None


async def _llm_evaluate(observation: str, model: str,
                        ollama_endpoint: str) -> dict:
    payload = {
        "model":  model,
        "system": DAST_SYSTEM_PROMPT,
        "prompt": observation,
        "stream": False,
        "options": {
            "temperature": 0.05,
            "num_predict": 3000,
            "stop": [],
        },
    }
    async with httpx.AsyncClient(timeout=120.0) as c:
        r = await c.post(f"{ollama_endpoint}/api/generate", json=payload)
        r.raise_for_status()
        raw = r.json().get("response", "").strip()


    import re
    m = re.search(r"```(?:json)?\s*(.*?)```", raw, re.DOTALL)
    if m:
        raw = m.group(1)
    start, end = raw.find("{"), raw.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(raw[start:end + 1])
        except json.JSONDecodeError:
            pass
    log.warning("dast_unparseable_llm_response")
    return {"has_finding": False, "missing_headers": [], "attack_surface": [],
            "findings": [], "risk_summary": "LLM response could not be parsed."}


def _build_observation(target_url: str, responses: list[tuple[str, httpx.Response]]) -> str:
    parts = [f"TARGET: {target_url}\n"]
    for url, resp in responses:
        headers = dict(resp.headers)

        safe_headers = {k: (v[:120] if len(v) > 120 else v) for k, v in headers.items()}
        missing = [h for h in EXPECTED_SECURITY_HEADERS if h not in headers]
        dom_preview = resp.text[:DOM_PREVIEW_LEN]
        parts.append(
            f"--- REQUEST: GET {url} ---\n"
            f"STATUS: {resp.status_code}\n"
            f"RESPONSE HEADERS:\n{json.dumps(safe_headers, indent=2)}\n"
            f"MISSING SECURITY HEADERS: {missing}\n"
            f"HTML/BODY (first {DOM_PREVIEW_LEN} chars):\n{dom_preview}\n"
        )
    return "\n".join(parts)


def _render_report(target_url: str, findings: dict) -> None:
    width = 60
    print("\n" + "=" * width)
    print("🛡️  KELAN DAST AGENT REPORT")
    print("=" * width)
    print(f"Target: {target_url}")
    print(f"Flaw detected: {'YES ⚠️' if findings.get('has_finding') else 'NO ✅'}")
    print()

    if findings.get("missing_headers"):
        print("Missing Security Headers:")
        for h in findings["missing_headers"]:
            print(f"  • {h}")
        print()

    if findings.get("attack_surface"):
        print("Attack Surface:")
        for a in findings["attack_surface"]:
            print(f"  • {a}")
        print()

    for f in findings.get("findings", []):
        sev = f.get("severity", "?")
        print(f"[{sev}] {f.get('cwe_id', '?')} — {f.get('title', '?')}")
        print(f"  Evidence:     {f.get('evidence', '')}")
        print(f"  Remediation:  {f.get('remediation', '')}")
        print()

    print(f"Risk Summary:\n  {findings.get('risk_summary', '')}")
    print("=" * width)


async def analyze_live_endpoint(
    target_url: str,
    model: str = DEFAULT_MODEL,
    ollama_endpoint: str = DEFAULT_ENDPOINT,
    json_out: str | None = None,
) -> dict:
    log.info("dast_start", target=target_url, model=model)

    async with httpx.AsyncClient() as client:
        responses = []


        resp = await _fetch(client, target_url)
        if resp is None:
            print(f"❌  Could not reach {target_url}. Is the server running?")
            return {}
        responses.append((target_url, resp))



        parsed = urllib.parse.urlparse(target_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        for probe in PROBE_PAYLOADS:
            probe_url = origin + probe
            r = await _fetch(client, probe_url)
            if r is not None:
                responses.append((probe_url, r))

    print("🧠  Evaluating with local Ollama engine…")
    observation = _build_observation(target_url, responses)
    findings = await _llm_evaluate(observation, model, ollama_endpoint)

    _render_report(target_url, findings)

    if json_out:
        with open(json_out, "w") as fh:
            json.dump(findings, fh, indent=2)
        print(f"[*] wrote {json_out}")

    return findings






async def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Kelan DAST — dynamic agentic scanner")
    parser.add_argument("--target",   default="http://localhost:8080",
                        help="Target URL (default: http://localhost:8080)")
    parser.add_argument("--model",    default=DEFAULT_MODEL,
                        help=f"Ollama model (default: {DEFAULT_MODEL})")
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT,
                        help="Ollama endpoint")
    parser.add_argument("--json",     dest="json_out",
                        help="Write JSON report to file")
    args = parser.parse_args(argv)

    print("\n🕵️  Kelan DAST Agent")
    print(f"   Target:  {args.target}")
    print(f"   Model:   {args.model}\n")

    result = await analyze_live_endpoint(
        target_url=args.target,
        model=args.model,
        ollama_endpoint=args.endpoint,
        json_out=args.json_out,
    )
    return 0 if result else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
