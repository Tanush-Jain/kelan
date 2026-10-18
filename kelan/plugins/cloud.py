
from __future__ import annotations

from pathlib import Path

from kelan.cloud.audit import audit_all
from kelan.core.plugin import PluginResult, ScanContext, ScanPlugin, ScopeKind


class CloudPlugin(ScanPlugin):
    name = "cloud"
    version = "0.1"
    description = "Cloud credentials, metadata exposures, public S3 buckets, IaC security checks"
    applies_to = {ScopeKind.CODEBASE, ScopeKind.REPO}

    async def run(self, ctx: ScanContext) -> PluginResult:
        root = (Path(ctx.target.value)
                if ctx.target.kind == ScopeKind.CODEBASE
                else ctx.workspace / "repo")
        cfg = ctx.config.section("cloud")

        check_buckets = cfg.get("check_buckets", False)
        findings = await audit_all(root, check_buckets=check_buckets)
        return PluginResult(plugin=self.name, findings=findings)
