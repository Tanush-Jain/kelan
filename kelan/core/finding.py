




from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @classmethod
    def from_any(cls, value: Any) -> "Severity":
        if isinstance(value, Severity):
            return value
        s = str(value or "INFO").upper()
        return cls(s) if s in cls._value2member_map_ else cls.INFO

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER.index(self.value)


class Confidence(str, Enum):
    NONE = "none"
    WEAK = "weak"
    MEDIUM = "medium"
    STRONG = "strong"

    @classmethod
    def from_any(cls, value: Any) -> "Confidence":
        if isinstance(value, Confidence):
            return value
        c = str(value or "none").lower()
        return cls(c) if c in cls._value2member_map_ else cls.NONE

    @property
    def rank(self) -> int:
        return {"none": 0, "weak": 1, "medium": 2, "strong": 3}[self.value]

    @staticmethod
    def at_least(conf: "Confidence", minimum: "Confidence") -> bool:
        return conf.rank >= minimum.rank


@dataclass
class Evidence:

    kind: str
    detail: str
    ref: str = ""
    snippet: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"kind": self.kind, "detail": self.detail, "ref": self.ref,
                "snippet": self.snippet[:400], "extra": self.extra}


@dataclass
class Finding:
    plugin: str
    category: str
    title: str
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.MEDIUM
    cwe: str = "CWE-710"
    remediation: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    target: str = ""
    location: str = ""
    detected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat())
    extra: dict = field(default_factory=dict)

    def add_evidence(self, kind: str, detail: str, ref: str = "",
                     snippet: str = "", **kw) -> "Finding":
        self.evidence.append(Evidence(kind, detail, ref, snippet, kw))
        return self

    def key(self) -> tuple:
        return (self.plugin, self.category, self.location,
                tuple(e.detail for e in self.evidence))

    def to_dict(self) -> dict:
        return {
            "plugin": self.plugin, "category": self.category, "title": self.title,
            "severity": self.severity.value, "confidence": self.confidence.value,
            "cwe": self.cwe, "remediation": self.remediation,
            "evidence": [e.to_dict() for e in self.evidence],
            "target": self.target, "location": self.location,
            "detected_at": self.detected_at, "extra": self.extra,
        }


class FindingSet:


    def __init__(self):
        self._items: list[Finding] = []
        self._seen: set = set()

    def add(self, f: Finding) -> bool:
        k = f.key()
        if k in self._seen:
            return False
        self._seen.add(k)
        self._items.append(f)
        return True

    def extend(self, items) -> int:
        added = 0
        for f in items:
            if self.add(f):
                added += 1
        return added

    @property
    def items(self) -> list[Finding]:
        return sorted(self._items,
                      key=lambda f: (f.severity.rank, f.location, f.plugin))

    def __len__(self):
        return len(self._items)

    def __iter__(self):
        return iter(self.items)

    def stats(self) -> dict:
        sev, cats, cwes, plugins = {}, {}, {}, {}
        for f in self._items:
            sev[f.severity.value] = sev.get(f.severity.value, 0) + 1
            cats[f.category] = cats.get(f.category, 0) + 1
            cwes[f.cwe] = cwes.get(f.cwe, 0) + 1
            plugins[f.plugin] = plugins.get(f.plugin, 0) + 1
        return {"findings": len(self._items), "severities": sev,
                "categories": cats, "cwes": cwes, "plugins": plugins}

    def gate(self, min_severity: str = "HIGH",
             min_confidence: str = "medium") -> int:

        threshold = Severity.from_any(min_severity).rank
        minc = Confidence.from_any(min_confidence)
        blockers = [f for f in self._items
                    if f.severity.rank <= threshold
                    and Confidence.at_least(f.confidence, minc)]
        return 1 if blockers else 0

    def to_dict(self) -> dict:
        return {"stats": self.stats(),
                "findings": [f.to_dict() for f in self.items]}

    def write_json(self, path: str) -> None:
        fd, tmp = tempfile.mkstemp(
            dir=os.path.dirname(os.path.abspath(path)) or ".")
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

    def write_html(self, path: str, tool_name: str = "kelan") -> None:
        sev_color = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#d97706",
                     "LOW": "#2563eb", "INFO": "#6b7280"}
        rows = []
        for f in self.items:
            ev = "; ".join(e.detail for e in f.evidence[:4])
            rows.append(
                f"<tr><td><span class='sev' style='background:{sev_color.get(f.severity.value, '#6b7280')}'>"
                f"{f.severity.value}</span></td>"
                f"<td>{f.confidence.value}</td><td>{f.cwe}</td>"
                f"<td>{f.plugin}</td><td>{f.title}</td>"
                f"<td><code>{f.location}</code></td><td>{ev}</td></tr>")
        html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>{tool_name} report</title>
<style>body{{font-family:system-ui,sans-serif;margin:2rem}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ddd;
padding:.5rem;text-align:left;font-size:.9rem}}
.sev{{color:#fff;padding:.15rem .5rem;border-radius:.25rem}}
code{{background:#f4f4f5;padding:.1rem .3rem}}</style></head><body>
<h1>{tool_name} — scan report</h1>
<p>{len(self.items)} findings</p>
<table><thead><tr><th>Severity</th><th>Confidence</th><th>CWE</th>
<th>Plugin</th><th>Title</th><th>Location</th><th>Evidence</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></body></html>"""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(html, encoding="utf-8")


    def to_sarif(self, tool_name: str = "kelan") -> dict:

        rules, results = {}, []
        for f in self._items:
            rid = f"kelan/{f.plugin}/{f.category}"
            if rid not in rules:
                rules[rid] = {
                    "id": rid, "name": f"{f.plugin}.{f.category}",
                    "shortDescription": {"text": f.title[:200]},
                    "properties": {"cwe": f.cwe, "severity": f.severity.value},
                }
            loc = {}
            if f.location:
                if ":" in f.location:
                    parts = f.location.rsplit(":", 1)
                    fp, ln = parts[0], parts[1]
                    try:
                        loc = {"physicalLocation": {
                            "artifactLocation": {"uri": fp},
                            "region": {"startLine": int(ln)}}}
                    except ValueError:
                        loc = {"physicalLocation": {
                            "artifactLocation": {"uri": f.location}}}
                else:
                    loc = {"physicalLocation": {
                        "artifactLocation": {"uri": f.location}}}
            level = ("error" if f.severity.rank <= 1
                     else "warning" if f.severity.rank <= 2 else "note")
            results.append({
                "ruleId": rid,
                "level": level,
                "message": {"text": f.title + " | " +
                            " | ".join(e.detail for e in f.evidence[:5])},
                "locations": [loc] if loc else [],
            })
        return {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {"driver": {"name": tool_name,
                                    "rules": list(rules.values())}},
                "results": results,
            }],
        }
