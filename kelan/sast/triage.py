# ══ Kelan SAST — LLM Triage Engine (Layer 3) ════════════════════════════════════
# License: MIT License (https://opensource.org/licenses/MIT)
# Copyright (c) 2026 Tanush Jain / Kelan Community
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

from __future__ import annotations

import json
import os
import re
from typing import Any

from kelan.ai.ollama_client import OllamaClient
from kelan.intel.db import IntelStore
from kelan.sast.rules.base import RuleFinding

DEFAULT_SAST_MODEL = os.getenv("KELAN_SAST_MODEL", os.getenv("KELAN_MODEL", "qwen2.5-coder:latest"))

TRIAGE_SYSTEM_PROMPT = """You are a senior application security engineer performing triage on verified SAST findings.
Your task is to analyze the source code evidence, call graph path, and intelligence context to assess real-world exploitability and suggest remediation.

STRICT CONSTRAINTS:
1. You may NOT alter the reachability verdict provided to you.
2. You may NOT invent new findings, files, or vulnerabilities.
3. You must respond strictly with valid JSON conforming to the requested schema. No conversational preamble.
"""


def extract_json_object(text: str) -> dict[str, Any] | None:
    if not text:
        return None
    # Strip markdown code blocks
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if m:
        text = m.group(1)
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        return json.loads(text[start : end + 1])
    except Exception:
        return None


class LLMTriageEngine:
    """Layer 3: LLM triage for reachable or unknown findings."""

    def __init__(
        self,
        endpoint: str = "http://127.0.0.1:11434",
        model: str | None = None,
        timeout: float = 30.0,
        temperature: float = 0.0,
    ) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.model = model or DEFAULT_SAST_MODEL
        self.timeout = int(timeout)
        self.temperature = temperature
        self.client = OllamaClient(
            endpoint=self.endpoint,
            model=self.model,
            timeout=self.timeout,
            temperature=self.temperature,
        )
        self.has_offline_failure = False

    async def triage_finding(
        self,
        finding: RuleFinding,
        intel_store: IntelStore | None = None,
    ) -> RuleFinding:
        """Evaluates exploitability of reachable or unknown findings. Skips unreachable findings."""
        # Layer constraint: only reachable or unknown findings receive triage
        if finding.reachability_verdict not in ("reachable", "unknown"):
            finding.llm_triage = {
                "status": "skipped_unreachable",
                "reason": "Finding is statically proven unreachable from all entrypoints.",
            }
            return finding

        # Collect intelligence context if available
        intel_context = self._get_intel_context(finding, intel_store)

        path_display = " -> ".join(finding.reachability_path) if finding.reachability_path else "(unknown dynamic path)"
        prompt = (
            f"Finding: {finding.title} [{finding.rule_id} / {finding.cwe}]\n"
            f"File: {finding.file_path}:{finding.line}-{finding.end_line}\n"
            f"Enclosing Function: {finding.enclosing_function or '<module>'}\n"
            f"Reachability Verdict: {finding.reachability_verdict}\n"
            f"Call Path: {path_display}\n"
            f"Sink: {finding.sink}\n"
            f"Evidence: {finding.source_to_sink_evidence}\n\n"
            f"Code Snippet:\n```\n{finding.snippet}\n```\n"
            f"{intel_context}\n"
            "Evaluate exploitability and provide a suggested fix. Respond ONLY with JSON matching this schema:\n"
            "{\n"
            '  "is_exploitable": true,\n'
            '  "exploitability_rating": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE",\n'
            '  "explanation": "concise explanation of exploitability given call path",\n'
            '  "suggested_fix": "exact remediation guidance or code replacement"\n'
            "}"
        )

        try:
            raw_text = await self.client.generate_json(
                prompt=prompt,
                system=TRIAGE_SYSTEM_PROMPT,
                max_tokens=400,
                temperature=self.temperature,
            )

            parsed = extract_json_object(raw_text)
            if parsed and isinstance(parsed, dict):
                rating = str(parsed.get("exploitability_rating", "MEDIUM")).upper()
                if rating not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"):
                    rating = "MEDIUM"

                finding.llm_triage = {
                    "status": "completed",
                    "model": self.model,
                    "is_exploitable": bool(parsed.get("is_exploitable", True)),
                    "exploitability_rating": rating,
                    "explanation": str(parsed.get("explanation", ""))[:1000],
                    "suggested_fix": str(parsed.get("suggested_fix", ""))[:1500],
                }
                return finding

            # If Ollama responded with invalid json
            finding.llm_triage = {
                "status": "degraded",
                "model": self.model,
                "reason": "Model response was not parseable as structured JSON.",
            }
        except Exception:
            # Graceful offline degradation: finding remains valid with deterministic evidence
            self.has_offline_failure = True
            finding.llm_triage = {
                "status": "offline_fallback",
                "model": self.model,
                "reason": "Ollama local inference service unreachable or offline.",
            }

        return finding

    def _get_intel_context(self, finding: RuleFinding, intel_store: IntelStore | None) -> str:
        if not intel_store:
            return ""
        try:
            records = intel_store.search(finding.cwe, limit=2)
            if not records:
                return ""
            lines = ["\nRelevant Intelligence Library Context:"]
            for rec in records:
                epss_str = f"{rec.epss_score:.2%}" if rec.epss_score is not None else "N/A"
                kev_str = "YES (Known Exploited)" if rec.is_kev else "No"
                desc = rec.description or rec.title
                lines.append(f"- Advisory {rec.id} (CVSS: {rec.cvss_score or 'N/A'}, EPSS: {epss_str}, KEV: {kev_str}): {desc[:120]}")
            return "\n".join(lines) + "\n"
        except Exception:
            return ""
