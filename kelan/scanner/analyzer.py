"""VulnerabilityAnalyzer — Ollama-backed SAST chunk analysis for kelan scan."""
import asyncio
import json
import re
from typing import Any, Optional

import structlog

from kelan.ai.ollama_client import OllamaClient
from kelan.scanner.prompts import (
    SCANNER_JSON_SCHEMA,
    SCANNER_SYSTEM_PROMPT,
    build_scan_prompt,
)

log = structlog.get_logger()

SAFE_DEFAULT = {"has_security_flaw": False, "findings": []}
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
FINDING_KEYS = (
    "cwe_id", "severity", "title", "description",
    "root_cause_analysis", "remediation",
)


def _extract_json_object(text: str) -> Optional[dict]:
    """Pull the first balanced JSON object out of a possibly noisy response."""
    if not text:
        return None
    # Gemma 4 may emit <|think|> / <|channel>... blocks — strip channel tags
    text = re.sub(r"<\|[^|]*\|>", "", text)
    m = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    if m:
        text = m.group(1)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        return json.loads(text[start:end + 1])
    except Exception:
        return None


def _coerce_finding(raw: Any) -> dict:
    """Enforce the finding sub-schema; discard malformed entries."""
    if not isinstance(raw, dict):
        raise ValueError("finding not an object")
    severity = str(raw.get("severity", "MEDIUM")).upper()
    if severity not in SEVERITIES:
        severity = "MEDIUM"
    return {
        "cwe_id": str(raw.get("cwe_id", "CWE-20"))[:64],
        "severity": severity,
        "title": str(raw.get("title", ""))[:160],
        "description": str(raw.get("description", ""))[:2000],
        "root_cause_analysis": str(raw.get("root_cause_analysis", ""))[:4000],
        "remediation": str(raw.get("remediation", ""))[:4000],
    }


def _validate_result(data: Any) -> dict:
    """Enforce SCANNER_JSON_SCHEMA shape; drop malformed findings."""
    if not isinstance(data, dict):
        return dict(SAFE_DEFAULT)
    raw_findings = data.get("findings")
    if not isinstance(raw_findings, list):
        raw_findings = []
    findings = []
    for f in raw_findings:
        try:
            findings.append(_coerce_finding(f))
        except (ValueError, TypeError):
            log.warning("scanner_dropped_malformed_finding")
    has_flaw = bool(data.get("has_security_flaw")) and bool(findings)
    return {"has_security_flaw": has_flaw, "findings": findings}


class VulnerabilityAnalyzer:
    """Analyze semantic code chunks with a local Ollama model (defensive SAST)."""

    def __init__(
        self,
        endpoint: str = "http://127.0.0.1:11434",
        model: str = "gemma4:31b",
        timeout: float = 180.0,
        max_tokens: int = 4000,
        temperature: float = 0.1,
    ):
        self._client = OllamaClient(
            endpoint=endpoint,
            model=model,
            timeout=int(timeout),
            temperature=temperature,
            max_tokens=max_tokens,
        )
        self._timeout = timeout

    async def analyze_chunk(self, chunk: dict) -> dict:
        """Analyze one chunk. Never raises — SAFE_DEFAULT on any failure."""
        try:
            raw = await asyncio.wait_for(
                self._client.generate_json(
                    prompt=build_scan_prompt(chunk),
                    system=SCANNER_SYSTEM_PROMPT,
                    max_tokens=self._client.max_tokens,
                    temperature=self._client.temperature,
                ),
                timeout=self._timeout,
            )
            data = _extract_json_object(raw)
            if data is None:
                log.warning(
                    "scanner_unparseable_response",
                    chunk=chunk.get("file_path"),
                )
                return dict(SAFE_DEFAULT)
            return _validate_result(data)
        except asyncio.TimeoutError:
            log.warning("scanner_timeout", chunk=chunk.get("file_path"))
        except Exception as exc:
            log.warning(
                "scanner_analyze_error",
                error=str(exc),
                chunk=chunk.get("file_path"),
            )
        return dict(SAFE_DEFAULT)

    async def close(self) -> None:
        await self._client.close()
