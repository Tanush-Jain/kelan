





from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable, Optional

import httpx

from kelan.core.finding import Confidence, Finding, Severity, Evidence

CATEGORY_CWE = {"runtime": "CWE-1333", "cloud": "CWE-798",
                "port": "CWE-1032", "dast": "CWE-79", "sca": "CWE-1104"}


@dataclass
class ChainRule:
    name: str
    description: str
    test: Callable[[list[dict]], bool]
    title: str
    severity: Severity = Severity.HIGH
    cwe: str = "CWE-710"
    remediation: str = ""

    def matches(self, findings: list[dict]) -> bool:
        try:
            return self.test(findings)
        except Exception:
            return False


def _by_plugin(findings: list[dict], plugin: str) -> list[dict]:
    return [f for f in findings if f.get("plugin") == plugin]


RULES: list[ChainRule] = [
    ChainRule(
        "open_debug_port_config_leak",
        "Open non-standard HTTP port + exposed actuator/env or swagger",
        lambda fs: (any(f.get("plugin") == "recon_ports"
                        and f.get("severity") == "LOW" and f.get("category") == "port"
                        for f in fs)
                    and any(f.get("plugin") == "dast"
                            and ("actuator" in f.get("title", "").lower()
                                 or "swagger" in f.get("title", "").lower())
                            for f in fs)),
        "Open debug port exposes configuration endpoints",
        Severity.CRITICAL, "CWE-200",
        "Close non-standard admin ports; disable actuator/env in prod; "
        "require auth on diagnostics endpoints."),
    ChainRule(
        "static_to_live_injection",
        "SAST found an injection sink AND DAST confirmed live evidence of "
        "the same class (e.g. sql-error signature or marker echo)",
        lambda fs: (any(f.get("plugin") == "sast"
                        and f.get("cwe") in ("CWE-89", "CWE-79", "CWE-78")
                        for f in fs)
                    and any(f.get("plugin") == "dast"
                            and f.get("confidence") == "strong"
                            for f in fs)),
        "Confirmed exploitable injection (static sink + live evidence)",
        Severity.CRITICAL, "CWE-89",
        "Fix the sink per remediation of both findings; add WAF + input "
        "validation as defense-in-depth."),
    ChainRule(
        "leaked_cred_reachability",
        "Hardcoded cloud credential in repo AND target host has a public "
        "endpoint on the same provider family",
        lambda fs: any(f.get("plugin") == "cloud"
                       and f.get("category") == "api_leak" for f in fs),
        "Cloud credential leak in reachable codebase",
        Severity.CRITICAL, "CWE-798",
        "Rotate immediately; scan git history; move to secret manager."),
    ChainRule(
        "unbounded_to_redos",
        "Runtime ReDoS confirmed on same file family as unbounded growth",
        lambda fs: any(f.get("plugin") == "analyze_runtime"
                       and f.get("confidence") == "strong" for f in fs),
        "Resource-exhaustion surface (ReDoS) with unbounded processing",
        Severity.HIGH, "CWE-1333",
        "Fix regex per runtime finding; add input length limits."),
]


def correlate(findings: list[Finding]) -> list[Finding]:
    f_dicts = [f.to_dict() for f in findings]
    chains: list[Finding] = []
    for rule in RULES:
        if rule.matches(f_dicts):
            f = Finding(plugin="chains", category="chain",
                        title=rule.title, severity=rule.severity,
                        confidence=Confidence.STRONG, cwe=rule.cwe,
                        remediation=rule.remediation)

            for src in findings:
                if src.plugin in ("recon_ports", "dast", "cloud", "sast", "analyze_runtime"):
                    f.add_evidence(
                        "chain_link",
                        src.title,
                        ref=src.location,
                        snippet=src.remediation
                    )
            chains.append(f)
    return chains


async def narrate_chain(finding: Finding,
                        endpoint: str = "http://127.0.0.1:11434",
                        model: str = "qwen2.5-coder:latest") -> Finding:


    evidence = [e.detail for e in finding.evidence]
    prompt = (
        "You are writing the narrative of a security finding for a report. "
        "Strict rules:\n"
        "1. Use ONLY the provided evidence bullets. Do not invent other "
        "vulnerabilities, targets, or impacts.\n"
        "2. Keep the category and CWE strictly as given.\n"
        "3. Return ONLY JSON: {\"narrative\": str}.\n"
        f"category: {finding.category}\n"
        f"cwe: {finding.cwe}\n"
        f"title: {finding.title}\n"
        f"evidence: {json.dumps(evidence)}\n")
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(f"{endpoint}/api/chat", json={
                "model": model, "stream": False, "format": "json",
                "messages": [{"role": "user", "content": prompt}]})
            r.raise_for_status()
            data = json.loads(r.json()["message"]["content"])
        narrative = str(data.get("narrative", ""))[:600]
        if narrative:
            finding.extra["narrative"] = narrative
    except (httpx.HTTPError, KeyError, json.JSONDecodeError, ValueError):
        pass
    return finding
