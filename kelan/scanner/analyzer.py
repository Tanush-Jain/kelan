
import asyncio
import json
import re
from typing import Any

import structlog

from kelan.ai.ollama_client import OllamaClient
from kelan.scanner.prompts import (
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


def _extract_json_object(text: str) -> dict | None:

    if not text:
        return None

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


def deterministic_scan_chunk(chunk: dict) -> list[dict]:
    findings = []
    content = chunk.get("content", "")
    file_path = chunk.get("file_path", "")

    # 1. SQL Injection (CWE-89)
    sqli_patterns = [
        (r'''(?i)\b(?:execute|raw_query|cursor\.execute)\s*\(\s*f["'].*?SELECT.*?\{''', "f-string formatted SQL query"),
        (r'''(?i)\b(?:execute|raw_query|cursor\.execute)\s*\(\s*["'].*?SELECT.*?%s.*?["']\s*%''', "% formatted SQL query"),
        (r'''(?i)\b(?:execute|raw_query|cursor\.execute)\s*\(\s*["'].*?SELECT.*?\s*["']\s*\+''', "concatenated SQL query"),
        (r'''(?i)\b(?:SELECT|INSERT|UPDATE|DELETE)\b.*?\bFROM\b.*?["']\s*\+\s*[a-zA-Z0-9_]+''', "SQL query string concatenation"),
    ]
    for pat, desc in sqli_patterns:
        if re.search(pat, content):
            findings.append({
                "cwe_id": "CWE-89",
                "severity": "CRITICAL",
                "title": f"SQL Injection: {desc}",
                "description": f"Potential SQL injection detected via unparameterized query construction in {file_path}.",
                "root_cause_analysis": "Dynamic parameters concatenated directly into SQL statements without parameter binding.",
                "remediation": "Use parameterized queries or ORM query abstractions (e.g. cursor.execute('SELECT * FROM tbl WHERE id = %s', (val,))).",
            })
            break

    # 2. Command Injection (CWE-78)
    cmdi_patterns = [
        (r'''(?i)\b(?:subprocess\.(?:Popen|run|call|check_call|check_output))\s*\([^)]*shell\s*=\s*True''', "subprocess execution with shell=True"),
        (r'''(?i)\bos\.(?:system|popen)\s*\(\s*(?:f["']|.*?[\+\%])''', "os.system or os.popen with dynamic arguments"),
        (r'''(?i)\bexec\s*\(\s*(?:req|request|user_input|param)''', "dynamic code execution with user parameters"),
    ]
    for pat, desc in cmdi_patterns:
        if re.search(pat, content):
            findings.append({
                "cwe_id": "CWE-78",
                "severity": "HIGH",
                "title": f"OS Command Injection: {desc}",
                "description": f"Unsanitized command execution detected in {file_path}.",
                "root_cause_analysis": "External commands executed through a shell with variables that could contain shell metacharacters.",
                "remediation": "Pass command arguments as an array without shell=True, or use shlex.quote() to sanitize parameters.",
            })
            break

    # 3. Insecure Deserialization (CWE-502)
    if re.search(r'''(?i)\bpickle\.(?:loads|load)\b''', content):
        findings.append({
            "cwe_id": "CWE-502",
            "severity": "HIGH",
            "title": "Insecure Deserialization: pickle usage",
            "description": "Arbitrary code execution risk from untrusted pickle deserialization.",
            "root_cause_analysis": "pickle can instantiate arbitrary Python objects and execute constructor payloads.",
            "remediation": "Use safer serialization formats such as JSON or Protocol Buffers.",
        })

    # 4. Hardcoded Secrets (CWE-798)
    secret_patterns = [
        (r'''(?i)(?:jwt_secret|api_key|secret_key|private_key|auth_token)\s*=\s*["'][A-Za-z0-9_\-]{16,}["']''', "Hardcoded secret or credential literal"),
        (r"-----[B]EGIN (?:RSA )?PRIVATE KEY-----", "Embedded private key"),
    ]
    for pat, desc in secret_patterns:
        if re.search(pat, content):
            findings.append({
                "cwe_id": "CWE-798",
                "severity": "HIGH",
                "title": f"Hardcoded Credential: {desc}",
                "description": "Sensitive credential or private key material found hardcoded in source.",
                "root_cause_analysis": "Secrets checked directly into source code risk exposure across repositories and builds.",
                "remediation": "Move credentials to environment variables or a secret management service.",
            })
            break

    return findings


class VulnerabilityAnalyzer:


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
        det_findings = deterministic_scan_chunk(chunk)
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
                return {
                    "has_security_flaw": bool(det_findings),
                    "findings": det_findings,
                    "llm_offline": False,
                }
            validated = _validate_result(data)
            # Merge deterministic findings without duplicate CWEs
            existing_cwes = {f.get("cwe_id") for f in validated.get("findings", [])}
            for df in det_findings:
                if df.get("cwe_id") not in existing_cwes:
                    validated["findings"].append(df)
            validated["has_security_flaw"] = bool(validated["findings"])
            validated["llm_offline"] = False
            return validated
        except TimeoutError:
            log.warning("scanner_timeout", chunk=chunk.get("file_path"))
        except Exception as exc:
            log.warning(
                "scanner_analyze_error",
                error=str(exc),
                chunk=chunk.get("file_path"),
            )
        return {
            "has_security_flaw": bool(det_findings),
            "findings": det_findings,
            "llm_offline": True,
        }

    async def close(self) -> None:
        await self._client.close()