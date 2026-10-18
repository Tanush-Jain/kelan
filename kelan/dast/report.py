
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

DEFAULT_REMEDIATION = {
    "xss": "Context-aware output encoding + CSP; input allowlist validation; HttpOnly/Secure cookies.",
    "sqli": "Parameterized queries / prepared statements everywhere; least-privilege DB roles; no raw SQL.",
    "cmdi": "Never pass user input to a shell; use exec APIs with argument lists; allowlist validation.",
    "traversal": "Canonicalize and resolve paths; enforce base-dir containment; reject encoded separators.",
    "ssti": "Treat templates as code; sandbox the template engine; never interpolate raw user input.",
    "header": "Set CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.",
    "idor": "Enforce server-side authorization per object; never trust client-supplied object ids.",
    "info": "",
}

DEFAULT_CWE = {
    "xss": "CWE-79", "sqli": "CWE-89", "cmdi": "CWE-78", "traversal": "CWE-22",
    "ssti": "CWE-1336", "header": "CWE-693", "idor": "CWE-639", "info": "CWE-710",
}
DEFAULT_SEV = {
    "xss": "HIGH", "sqli": "HIGH", "cmdi": "CRITICAL", "traversal": "HIGH",
    "ssti": "HIGH", "header": "LOW", "idor": "HIGH", "info": "LOW",
}


@dataclass
class Finding:
    url: str
    method: str
    param: str
    category: str
    title: str
    evidence: str
    remediation: str = ""
    cwe: str = "CWE-710"
    severity: str = "LOW"
    payload: str = ""
    variant: str = ""
    confidence: str = "medium"
    detected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def key(self) -> tuple:
        return (self.url, self.method, self.param, self.category, self.variant)


class Report:
    def __init__(self, target: str, model: str):
        self.target = target
        self.model = model
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.finished_at: Optional[str] = None
        self.findings: list[Finding] = []
        self.meta: dict = {}
        self.risk_summary: str = ""

    def add(self, f: Finding):
        if f.cwe == "CWE-710":
            f.cwe = DEFAULT_CWE.get(f.category, "CWE-710")
        if f.severity == "LOW" and f.category in DEFAULT_SEV:
            f.severity = DEFAULT_SEV[f.category]
        if not f.remediation:
            f.remediation = DEFAULT_REMEDIATION.get(f.category, "")
        if not any(f.key() == x.key() for x in self.findings):
            self.findings.append(f)

    def sort(self):
        self.findings.sort(
            key=lambda f: (SEV_ORDER.get(f.severity, 9), f.url, f.param)
        )

    def finalize(self):
        self.finished_at = datetime.now(timezone.utc).isoformat()
        self.sort()

    def stats(self) -> dict:
        sev, cats, cwes = {}, {}, {}
        for f in self.findings:
            sev[f.severity] = sev.get(f.severity, 0) + 1
            cats[f.category] = cats.get(f.category, 0) + 1
            cwes[f.cwe] = cwes.get(f.cwe, 0) + 1
        return {"severities": sev, "categories": cats, "cwes": cwes}

    def to_dict(self) -> dict:
        return {
            "tool": "kelan-dast",
            "target": self.target,
            "model": self.model,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "meta": self.meta,
            "risk_summary": self.risk_summary,
            "stats": self.stats(),
            "findings": [
                {k: v for k, v in f.__dict__.items()}
                for f in self.findings
            ],
        }

    def write_json(self, path: str):
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)) or ".")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self.to_dict(), fh, indent=2)
            os.replace(tmp, path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def gate(self, min_severity: str) -> int:

        threshold = SEV_ORDER.get(min_severity.upper(), 1)
        blockers = [
            f for f in self.findings
            if SEV_ORDER.get(f.severity, 9) <= threshold
            and f.confidence in ("medium", "strong")
        ]
        return 1 if blockers else 0
