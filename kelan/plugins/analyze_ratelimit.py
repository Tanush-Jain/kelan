
from __future__ import annotations

from kelan.core.finding import Finding
from kelan.core.plugin import PluginResult, ScanContext, ScanPlugin, ScopeKind
from kelan.analyze.ratelimit import audit_codebase


class AnalyzeRatelimitPlugin(ScanPlugin):
    name = "analyze_ratelimit"
    version = "0.1"
    description = "Static analysis of rate limit / token bucket implementation flaws"
    applies_to = {ScopeKind.CODEBASE, ScopeKind.REPO}

    async def run(self, ctx: ScanContext) -> PluginResult:
        target_path = ctx.target.value
        if ctx.target.kind == ScopeKind.REPO:
            target_path = str(ctx.workspace / "repo")
            
        findings = audit_codebase(target_path)
        return PluginResult(plugin=self.name, findings=findings)
