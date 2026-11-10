# ══ Kelan SAST Adapter Plugin ══════════════════════════════════════════════════
# License: MIT License (https://opensource.org/licenses/MIT)

from __future__ import annotations

import asyncio
from pathlib import Path

from kelan.core.finding import Confidence, Finding, Severity
from kelan.core.plugin import PluginResult, ScanContext, ScanPlugin, ScopeKind
from kelan.sast.engine import SastEngine
from kelan.sast.rules.base import RuleConfidence


class SastPlugin(ScanPlugin):
    name = "sast"
    version = "0.2"
    description = "Static analysis: Deterministic AST rules, reachability call graph, and optional LLM triage"
    applies_to = {ScopeKind.CODEBASE, ScopeKind.REPO}

    async def run(self, ctx: ScanContext) -> PluginResult:
        target_path = (
            ctx.target.value if ctx.target.kind == ScopeKind.CODEBASE else None
        )
        if ctx.target.kind == ScopeKind.REPO:
            repo = ctx.target.value
            clone_dir = ctx.workspace / "repo"
            proc = await asyncio.create_subprocess_exec(
                "git",
                "clone",
                "--depth",
                "1",
                repo,
                str(clone_dir),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await proc.wait()
            if proc.returncode != 0:
                return PluginResult(self.name, errors=[f"git clone failed: {repo}"])
            target_path = str(clone_dir)

        if target_path is None:
            return PluginResult(self.name, errors=["No codebase target path provided"])

        root = Path(target_path)
        excludes = set(
            ctx.config.section("sast").get(
                "exclude",
                (".git", "node_modules", "venv", ".venv", "target", "dist", "build"),
            )
        )

        use_llm = bool(ctx.config.get("use_llm", True))
        model = (ctx.ollama or {}).get("model", "qwen2.5-coder:latest")
        endpoint = (ctx.ollama or {}).get("endpoint", "http://127.0.0.1:11434")

        engine = SastEngine(endpoint=endpoint, model=model)

        pr = PluginResult(plugin=self.name)

        files = [
            p
            for p in root.rglob("*")
            if p.is_file()
            and not any(part in excludes for part in p.parts)
            and p.suffix.lower() in (".py", ".js", ".ts", ".tsx", ".mjs", ".cjs")
        ]

        if not files:
            pr.meta = {
                "files_scanned": 0,
                "findings_count": 0,
                "status": "No supported source files found",
            }
            return pr

        raw_findings = await engine.scan_directory(
            directory=root,
            excludes=excludes,
            use_reachability=True,
            use_llm=use_llm,
            concurrency=ctx.config.get("sast_concurrency", 4),
        )

        for rf in raw_findings:
            conf = (
                Confidence.STRONG
                if rf.confidence == RuleConfidence.HIGH
                else (
                    Confidence.MEDIUM
                    if rf.confidence == RuleConfidence.MEDIUM
                    else Confidence.WEAK
                )
            )

            f = Finding(
                plugin="sast",
                category="sast",
                title=rf.title,
                severity=Severity.from_any(rf.severity.value),
                confidence=conf,
                cwe=rf.cwe,
                remediation=rf.remediation,
                location=f"{rf.file_path}:{rf.line}",
                target=rf.file_path,
                extra={
                    "rule_id": rf.rule_id,
                    "enclosing_function": rf.enclosing_function,
                    "reachability_verdict": rf.reachability_verdict,
                    "reachability_path": rf.reachability_path,
                    "llm_triage": rf.llm_triage,
                },
            )

            f.add_evidence(
                "ast_rule",
                rf.description,
                ref=f"{rf.file_path}:{rf.line}",
                snippet=rf.snippet,
                rule_id=rf.rule_id,
                source_to_sink_evidence=rf.source_to_sink_evidence,
            )

            f.add_evidence(
                "reachability",
                f"Verdict: {rf.reachability_verdict}",
                ref=rf.enclosing_function or "<module>",
                path=rf.reachability_path,
            )

            if rf.llm_triage and rf.llm_triage.get("status") == "completed":
                f.add_evidence(
                    "llm_triage",
                    rf.llm_triage.get("explanation", ""),
                    ref=f"Model: {rf.llm_triage.get('model')}",
                    exploitability=rf.llm_triage.get("exploitability_rating"),
                    suggested_fix=rf.llm_triage.get("suggested_fix"),
                )

            pr.findings.append(f)

        is_offline = engine.triage_engine.has_offline_failure
        pr.meta = {
            "files_scanned": len(files),
            "findings_count": len(pr.findings),
            "llm_status": (
                "offline (deterministic fallback active)"
                if is_offline
                else ("online" if use_llm else "N/A (Deterministic)")
            ),
            "layers": (
                ["Layer 1: Deterministic AST", "Layer 2: Reachability Call Graph"]
                + (["Layer 3: LLM Triage"] if use_llm else [])
            ),
            "model": model if use_llm else "N/A (Deterministic)",
        }
        if is_offline:
            pr.errors.append("Ollama LLM was unreachable during SAST scan; deterministic rule engine was used.")

        return pr
