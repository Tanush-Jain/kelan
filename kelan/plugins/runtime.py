
from __future__ import annotations
from pathlib import Path

from kelan.analyze.runtime import audit_codebase
from kelan.core.plugin import (PluginResult, ScanContext, ScanPlugin, ScopeKind)


class AnalyzeRuntimePlugin(ScanPlugin):
    name = "analyze_runtime"
    version = "0.1"
    description = ("Runtime/resource-exhaustion audit: ReDoS (subprocess-"
                   "validated), zip bombs, unbounded growth, dangerous sinks")
    applies_to = {ScopeKind.CODEBASE, ScopeKind.REPO}

    async def run(self, ctx: ScanContext) -> PluginResult:
        root = (Path(ctx.target.value)
                if ctx.target.kind == ScopeKind.CODEBASE
                else ctx.workspace / "repo")
        cfg = ctx.config.section("analyze_runtime")
        findings = audit_codebase(
            root,
            validate_redos=cfg.get("validate_redos", True),
            redos_timeout=cfg.get("redos_timeout", 1.5))
        pr = PluginResult(plugin=self.name, findings=findings)
        pr.meta = {"redos_validated": any(
            f.confidence.value == "strong" for f in findings)}
        return pr
