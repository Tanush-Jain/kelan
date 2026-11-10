# ══ Kelan SAST — Rule Base Definitions ════════════════════════════════════════
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

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RuleSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RuleConfidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class RuleFinding:
    rule_id: str
    cwe: str
    title: str
    description: str
    severity: RuleSeverity
    confidence: RuleConfidence
    file_path: str
    line: int
    end_line: int
    snippet: str
    sink: str
    source_to_sink_evidence: str
    remediation: str
    enclosing_function: str = ""
    reachability_verdict: str = "unknown"  # "reachable" | "unreachable" | "unknown"
    reachability_path: list[str] = field(default_factory=list)
    llm_triage: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "cwe": self.cwe,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "file_path": self.file_path,
            "line": self.line,
            "end_line": self.end_line,
            "snippet": self.snippet,
            "sink": self.sink,
            "source_to_sink_evidence": self.source_to_sink_evidence,
            "remediation": self.remediation,
            "enclosing_function": self.enclosing_function,
            "reachability_verdict": self.reachability_verdict,
            "reachability_path": self.reachability_path,
            "llm_triage": self.llm_triage,
        }


class SastRule:
    """Base class for AST-based deterministic detection rules."""

    rule_id: str = "KELAN-GEN-00"
    cwe: str = "CWE-20"
    title: str = "Generic Flaw"
    severity: RuleSeverity = RuleSeverity.MEDIUM
    confidence: RuleConfidence = RuleConfidence.MEDIUM
    remediation: str = "Review and sanitize input."
    languages: tuple[str, ...] = ("python",)

    def scan_file(self, file_path: str, code: str, root_node: Any) -> list[RuleFinding]:
        raise NotImplementedError
