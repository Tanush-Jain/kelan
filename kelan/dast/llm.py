"""Optional Ollama summarizer — narrative only. Detection is deterministic;
the model may refine title/remediation/CWE but cannot create or delete findings."""
from __future__ import annotations

import json
import re

import httpx
import structlog

log = structlog.get_logger()

_SYSTEM = (
    "You are a defensive DAST report writer. You are given deterministic "
    "findings with evidence. Do NOT invent findings, do NOT change their "
    "severity or confidence. For each finding return cwe_id, title, remediation. "
    "Respond ONLY with JSON: "
    '{"results": [{"idx": 0, "cwe_id": "CWE-89", "title": "...", '
    '"remediation": "..."}], "risk_summary": "1-3 sentence summary"}'
)


def _extract_json(text: str):
    if not text:
        return None
    text = re.sub(r"<\|[^|]*\|>", "", text)  # strip Gemma think/channel tags
    m = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    if m:
        text = m.group(1)
    s, e = text.find("{"), text.rfind("}")
    if s == -1 or e <= s:
        return None
    try:
        return json.loads(text[s:e + 1])
    except Exception:
        return None


async def summarize_findings(endpoint: str, model: str, findings, target: str,
                             timeout: float = 120.0):
    if not findings:
        return {}, None
    payload = [
        {"idx": i, "url": f.url, "param": f.param, "category": f.category,
         "cwe": f.cwe, "severity": f.severity, "evidence": f.evidence}
        for i, f in enumerate(findings)
    ]
    prompt = (
        f"Target: {target}\n\nFindings:\n{json.dumps(payload, indent=2)}\n\n"
        "Respond ONLY with the JSON object described in the system prompt."
    )
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.post(f"{endpoint.rstrip('/')}/api/generate", json={
                "model": model,
                "system": _SYSTEM,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.2, "num_predict": 2000, "stop": []},
            })
            r.raise_for_status()
        data = _extract_json(r.json().get("response", "")) or {}
    except Exception as exc:
        log.warning("llm_summarize_failed", error=str(exc))
        return {}, None

    updates = {}
    for item in (data.get("results") or []):
        try:
            idx = int(item.get("idx", -1))
        except (TypeError, ValueError):
            continue
        if 0 <= idx < len(findings):
            updates[idx] = item
    return updates, data.get("risk_summary")
