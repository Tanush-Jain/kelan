
from __future__ import annotations

from kelan.chains.correlation import correlate, narrate_chain
from kelan.core.plugin import PluginResult, ScanContext, ScanPlugin, ScopeKind


class ChainsPlugin(ScanPlugin):
    name = "chains"
    version = "0.1"
    description = "Correlates findings from multiple plugins to identify multi-stage attack chains"
    applies_to = {ScopeKind.CODEBASE, ScopeKind.REPO, ScopeKind.URL, ScopeKind.HOST}
    requires = ("sast", "dast", "cloud", "analyze_runtime", "recon_ports", "sca")

    async def run(self, ctx: ScanContext) -> PluginResult:

        findings = correlate(ctx.results.items)
        

        if ctx.ollama:
            endpoint = ctx.ollama.get("endpoint", "http://127.0.0.1:11434")
            model = ctx.ollama.get("model", "qwen2.5-coder:latest")
            for f in findings:
                await narrate_chain(f, endpoint=endpoint, model=model)
                
        return PluginResult(plugin=self.name, findings=findings)
