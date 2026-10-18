




from __future__ import annotations

import asyncio
import re
import shutil
import json
from pathlib import Path

import httpx

from kelan.core.finding import Confidence, Finding, Severity

EXCLUDE = {".git", "node_modules", "venv", ".venv", "target", "__pycache__"}


CRED_RULES = [
    ("aws", "AWS Access Key ID",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b"), Severity.HIGH),
    ("aws", "AWS Secret Access Key",
     re.compile(r"\b(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['\"][A-Za-z0-9/+=]{40}['\"]"),
     Severity.HIGH),
    ("aws", "AWS Session Token",
     re.compile(r"\b(?:aws_session_token|AWS_SESSION_TOKEN)\s*[=:]\s*['\"][A-Za-z0-9/+=]{100,}['\"]"),
     Severity.HIGH),
    ("gcp", "GCP Service Account JSON",
     re.compile(r'"type"\s*:\s*"service_account"'), Severity.HIGH),
    ("azure", "Azure Storage/App key",
     re.compile(r"\bAccountKey[=:]\s*[A-Za-z0-9+/=]{40,}"), Severity.MEDIUM),
    ("stripe", "Stripe Live Secret Key",
     re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}"), Severity.CRITICAL),
    ("sendgrid", "SendGrid API Key",
     re.compile(r"\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}"), Severity.HIGH),
    ("slack", "Slack Token",
     re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}"), Severity.HIGH),
    ("github", "GitHub Personal Access Token",
     re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}"), Severity.HIGH),
    ("openai", "OpenAI API Key",
     re.compile(r"\bsk-proj-[0-9A-Za-z_-]{20,}"), Severity.HIGH),
]
META_IP = "169.254.169.254"
S3_PUBLIC_RE = re.compile(r"(?:https?://)?([a-z0-9.-]+)\.s3\.(?:[a-z0-9-]+\.)?amazonaws\.com", re.I)


def audit_creds(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or any(x in EXCLUDE for x in p.parts):
            continue
        try:
            text = p.read_text(errors="ignore")
        except OSError:
            continue
        for provider, name, regex, sev in CRED_RULES:
            for m in regex.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                f = Finding(
                    plugin="cloud", category="api_leak",
                    title=f"{name} leaked ({provider})",
                    severity=sev, confidence=Confidence.STRONG,
                    cwe="CWE-798",
                    remediation=(f"Rotate the {provider} credential "
                                 "immediately, revoke from history/git "
                                 "history, and move it to a secret manager."),
                    location=f"{p}:{line}", target=str(p),
                )
                f.add_evidence("secret", name, ref=f"{p}:{line}",
                               snippet=m.group(0)[:12] + "…[redacted]")
                findings.append(f)

        if META_IP in text:
            line = text.count("\n", 0, text.find(META_IP)) + 1
            findings.append(Finding(
                plugin="cloud", category="cloud_misconfig",
                title="Instance metadata endpoint (169.254.169.254) accessed",
                severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                cwe="CWE-918",
                remediation="Block outbound access to the link-local metadata "
                            "IP in network policy / egress rules.",
                location=f"{p}:{line}", target=str(p),
            ).add_evidence("advisory", "code reaches cloud metadata endpoint",
                           ref=f"{p}:{line}"))
    return findings


async def check_s3_bucket(bucket: str, timeout: float = 10) -> Finding | None:

    url = f"https://{bucket}.s3.amazonaws.com/"
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as c:
            r = await c.get(url)
    except httpx.HTTPError:
        return None
    if r.status_code == 200 and "<ListBucketResult" in r.text:
        return Finding(
            plugin="cloud", category="cloud_misconfig",
            title=f"S3 bucket {bucket} allows public listing",
            severity=Severity.HIGH, confidence=Confidence.STRONG,
            cwe="CWE-200",
            remediation="Block public ListBucket via bucket policy / ACL; "
                        "enable Block Public Access.",
            target=url,
        ).add_evidence("http_status", "public ListBucketResult returned",
                       ref=url)
    return None


async def find_public_buckets(root: Path) -> list[Finding]:

    findings: list[Finding] = []
    buckets = set()
    for p in root.rglob("*"):
        if not p.is_file() or any(x in EXCLUDE for x in p.parts):
            continue
        try:
            text = p.read_text(errors="ignore")
        except OSError:
            continue
        for m in S3_PUBLIC_RE.finditer(text):
            buckets.add(m.group(1))
    for b in sorted(buckets):
        if f := await check_s3_bucket(b):
            findings.append(f)
    return findings


async def _run_iac_tool(tool: str, root: Path):
    args = [tool, "--json"] if tool == "checkov" else [tool, "-f", "json"]
    try:
        proc = await asyncio.create_subprocess_exec(
            tool, *args, cwd=str(root),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        stdout, _ = await proc.communicate()
        return proc.returncode, stdout
    except FileNotFoundError:
        return None, None


def _parse_iac_json(text: str, tool: str) -> list[Finding]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    out = []
    checks = data.get("results", {}).get("failed_checks", []) if tool == "checkov" \
        else data.get("results", [])
    if not isinstance(checks, list):
        return []
    for c in checks:
        f = Finding(
            plugin="cloud", category="iac_misconfig",
            title=c.get("check_name", c.get("rule_description", "IaC finding")),
            severity=Severity.from_any(c.get("severity", "MEDIUM")),
            confidence=Confidence.STRONG, cwe="CWE-693",
            remediation=c.get("guideline", ""),
            location=f"{c.get('file_path', '')}:{c.get('file_line_range', [0])[0]}",
        )
        f.add_evidence("iac", c.get("check_id", ""), ref=c.get("file_path", ""))
        out.append(f)
    return out


async def audit_iac(root: Path) -> list[Finding]:

    findings: list[Finding] = []
    if not any(root.rglob("*.tf")) and not any(root.rglob("*.yml")) and not any(root.rglob("*.yaml")):
        return findings
    for tool in ("tfsec", "checkov"):
        if not shutil.which(tool):
            continue
        code, out_bytes = await _run_iac_tool(tool, root)
        if out_bytes:
            out = out_bytes.decode(errors="ignore")
            findings += _parse_iac_json(out, tool)
    return findings


async def audit_all(root: str | Path, check_buckets: bool = False) -> list[Finding]:
    root = Path(root)
    findings = audit_creds(root)
    if check_buckets:
        findings += await find_public_buckets(root)
    findings += await audit_iac(root)
    return findings
