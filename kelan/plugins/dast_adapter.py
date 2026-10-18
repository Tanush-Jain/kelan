




from __future__ import annotations

from kelan.core.finding import Confidence, Finding, Severity, Evidence
from kelan.core.plugin import PluginResult, ScanContext, ScanPlugin, ScopeKind


def _sev(s: str) -> Severity:
    return Severity.from_any(s)


def _conf(c: str) -> Confidence:
    return Confidence.from_any(c)


class DastPlugin(ScanPlugin):
    name = "dast"
    version = "0.2"
    description = "Dynamic app security testing (crawl, probes, bypass encodings)"
    applies_to = {ScopeKind.URL}
    requires = ("recon_ports",)

    async def run(self, ctx: ScanContext) -> PluginResult:
        from kelan.dast.pipeline import run_scan, ScanOptions

        target_url = ctx.target.value
        cfg = ctx.config.section("dast")

        opts = ScanOptions(
            target=target_url,
            max_depth=cfg.get("max_depth", 3),
            max_pages=cfg.get("max_pages", 15),
            delay=cfg.get("delay", 0.5),
            concurrency=cfg.get("concurrency", 2),
            timeout=cfg.get("timeout", 15.0),
            use_llm=bool(ctx.ollama),
            bypass=cfg.get("bypass", True),
            external=cfg.get("external", False),
            fuzz_tokens=cfg.get("fuzz_tokens", False),
        )


        res = await run_scan(opts)
        findings = []
        for f in res.findings:
            uf = Finding(
                plugin=self.name,
                category=f.category,
                title=f.title,
                severity=_sev(f.severity),
                confidence=_conf(f.confidence),
                cwe=f.cwe,
                remediation=f.remediation,
                target=f.url,
                location=f.url if f.param == "-" else f"{f.url} (param: {f.param}, method: {f.method})",
            )
            uf.add_evidence(
                kind="http_status" if f.category == "header" else "reflection",
                detail=f.evidence,
                ref=f.url,
                snippet=f.payload or f.variant,
            )
            findings.append(uf)

        pr = PluginResult(plugin=self.name, findings=findings)
        pr.meta = {
            "findings_count": len(findings),
        }
        return pr
