# ══ Kelan SAST — Unified 3-Layer SAST Engine ═══════════════════════════════════
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

import asyncio
from pathlib import Path

from kelan.intel.db import IntelStore
from kelan.sast.reachability import ReachabilityEvaluator, TreeSitterCallGraphBuilder
from kelan.sast.rules.base import RuleFinding, SastRule
from kelan.sast.rules.go_rules import GO_RULES
from kelan.sast.rules.javascript_rules import JAVASCRIPT_RULES
from kelan.sast.rules.python_rules import PYTHON_RULES
from kelan.sast.triage import DEFAULT_SAST_MODEL, LLMTriageEngine


class SastEngine:
    """Unified SAST engine orchestrating:
    Layer 1: Deterministic AST rules (Python, JS, TS)
    Layer 2: Reachability call graph analysis
    Layer 3: LLM triage for reachable & unknown findings
    """

    def __init__(
        self,
        endpoint: str = "http://127.0.0.1:11434",
        model: str | None = None,
        intel_store: IntelStore | None = None,
    ) -> None:
        self.endpoint = endpoint
        self.model = model or DEFAULT_SAST_MODEL
        self.builder = TreeSitterCallGraphBuilder()
        self.reachability_evaluator = ReachabilityEvaluator()
        self.triage_engine = LLMTriageEngine(endpoint=self.endpoint, model=self.model)
        self.intel_store = intel_store

        self.python_rules: list[SastRule] = list(PYTHON_RULES)
        self.js_rules: list[SastRule] = list(JAVASCRIPT_RULES)
        self.go_rules: list[SastRule] = list(GO_RULES)

    def scan_code_sync(
        self,
        file_path: str,
        code: str,
        use_reachability: bool = True,
    ) -> list[RuleFinding]:
        """Synchronous scan executing Layer 1 (Deterministic AST) and optionally Layer 2 (Reachability)."""
        ext = Path(file_path).suffix.lower()
        if ext not in (".py", ".js", ".ts", ".tsx", ".mjs", ".cjs", ".go"):
            return []

        tree = self.builder.parse(file_path, code)
        if tree is None:
            return []

        if ext == ".py":
            rules = self.python_rules
        elif ext == ".go":
            rules = self.go_rules
        else:
            rules = self.js_rules
        findings: list[RuleFinding] = []

        # Layer 1: Deterministic AST rules
        for rule in rules:
            try:
                res = rule.scan_file(file_path, code, tree.root_node)
                findings.extend(res)
            except Exception:
                continue

        # Layer 2: Reachability Call Graph
        if use_reachability and findings:
            try:
                findings = self.reachability_evaluator.evaluate_findings(
                    file_path=file_path,
                    code=code,
                    root_node=tree.root_node,
                    findings=findings,
                )
            except Exception:
                pass

        return findings

    async def scan_code(
        self,
        file_path: str,
        code: str,
        use_reachability: bool = True,
        use_llm: bool = False,
    ) -> list[RuleFinding]:
        """Executes Layer 1 and Layer 2, plus Layer 3 (LLM triage) if requested."""
        findings = self.scan_code_sync(file_path, code, use_reachability=use_reachability)

        if use_llm and findings:
            tasks = [
                self.triage_engine.triage_finding(f, intel_store=self.intel_store)
                for f in findings
            ]
            findings = await asyncio.gather(*tasks)

        return findings

    async def scan_file(
        self,
        path: Path | str,
        use_reachability: bool = True,
        use_llm: bool = False,
    ) -> list[RuleFinding]:
        path_obj = Path(path)
        if not path_obj.is_file():
            return []

        try:
            with open(path_obj, "r", encoding="utf-8", errors="replace") as f:
                code = f.read()
        except Exception:
            return []

        return await self.scan_code(
            file_path=str(path_obj),
            code=code,
            use_reachability=use_reachability,
            use_llm=use_llm,
        )

    async def scan_directory(
        self,
        directory: Path | str,
        excludes: set[str] | None = None,
        use_reachability: bool = True,
        use_llm: bool = False,
        concurrency: int = 4,
    ) -> list[RuleFinding]:
        root = Path(directory)
        if not root.is_dir():
            return []

        exclude_set = excludes or {".git", "node_modules", "venv", ".venv", "target", "dist", "build"}
        files: list[Path] = [
            p for p in root.rglob("*")
            if p.is_file()
            and not any(part in exclude_set for part in p.parts)
            and p.suffix.lower() in (".py", ".js", ".ts", ".tsx", ".mjs", ".cjs", ".go")
        ]

        sem = asyncio.Semaphore(concurrency)

        async def _guarded(p: Path) -> list[RuleFinding]:
            async with sem:
                return await self.scan_file(p, use_reachability=use_reachability, use_llm=use_llm)

        results = await asyncio.gather(*(_guarded(p) for p in files), return_exceptions=True)
        all_findings: list[RuleFinding] = []
        for r in results:
            if isinstance(r, list):
                all_findings.extend(r)

        return all_findings
