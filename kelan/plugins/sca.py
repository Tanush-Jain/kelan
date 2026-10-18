



from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
from pathlib import Path
from typing import Optional

import httpx
import structlog

from kelan.core.finding import Confidence, Finding, Severity
from kelan.core.plugin import PluginResult, ScanContext, ScanPlugin, ScopeKind

log = structlog.get_logger()

SEV_MAP = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM",
           "MEDIUM": "MEDIUM", "LOW": "LOW"}

_ECOSYSTEM = {
    "requirements.txt": "PyPI",
    "Pipfile": "PyPI",
    "poetry.lock": "PyPI",
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "go.mod": "Go",
    "Gemfile.lock": "RubyGems",
    "default.lock": "Maven",
}
_SPEC_RE = re.compile(r"([A-Za-z0-9_.-]+)[\s===]+([0-9][A-Za-z0-9._-]*)")


def _cwe_from_aliases(aliases: list[str]) -> str:

    return "CWE-1035"


class ScaPlugin(ScanPlugin):
    name = "sca"
    version = "0.1"
    description = "Software composition analysis: OSV + pip-audit + npm audit"
    applies_to = {ScopeKind.REPO, ScopeKind.CODEBASE}

    async def run(self, ctx: ScanContext) -> PluginResult:
        root = Path(ctx.target.value) if ctx.target.kind == ScopeKind.CODEBASE \
            else ctx.workspace / "repo"
        pr = PluginResult(plugin=self.name)


        for tool, args in (("osv-scanner", ["--json"]),
                           ("pip-audit", ["--format", "json"]),
                           ("npm", ["audit", "--json"])):
            if shutil.which(tool):
                try:
                    pr.findings.extend(await self._run_tool(tool, args, root))
                except Exception as exc:
                    pr.errors.append(f"{tool}: {exc}")


        if not shutil.which("osv-scanner") and \
                not shutil.which("pip-audit") and not shutil.which("npm"):
            reqs = await self._collect_manifests(root)
            if reqs:
                pr.findings.extend(await self._osv_query(reqs))

        return pr

    async def _run_tool(self, tool: str, args: list[str],
                        root: Path) -> list[Finding]:
        proc = await asyncio.create_subprocess_exec(
            tool, *args, cwd=str(root),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        out, _ = await proc.communicate()
        text = out.decode("utf-8", "replace")
        findings: list[Finding] = []
        if tool == "osv-scanner":
            findings += self._parse_osv_scanner(text, root)
        elif tool == "pip-audit":
            findings += self._parse_pip_audit(text)
        elif tool == "npm":
            findings += self._parse_npm(text)
        return findings

    def _parse_osv_scanner(self, text: str, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return findings
        for result in data.get("results", []):
            for pkg in result.get("packages", []):
                pkg_name = pkg.get("package", {}).get("name", "?")
                version = pkg.get("package", {}).get("version", "?")
                loc = pkg.get("location", {}).get("path", "")
                for vuln in pkg.get("vulnerabilities", []):
                    aliases = [a for a in vuln.get("aliases", [])
                               if a.upper().startswith("CVE-")
                               or a.upper().startswith("GHSA-")]
                    f = Finding(
                        plugin="sca", category="sca",
                        title=f"{pkg_name}@{version}: "
                              f"{vuln.get('id', 'unknown advisory')}",
                        severity=Severity.from_any(
                            vuln.get("severity", "MEDIUM")),
                        confidence=Confidence.STRONG,
                        cwe=_cwe_from_aliases(aliases),
                        remediation=f"Upgrade {pkg_name} "
                                    f"(affects {version}).",
                        location=f"{loc}:{pkg_name}@{version}",
                        target=str(root),
                    )
                    f.add_evidence("manifest", vuln.get("id", ""),
                                   ref=",".join(aliases) or pkg_name,
                                   detail=vuln.get("summary", ""))
                    findings.append(f)
        return findings

    def _parse_pip_audit(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return findings
        for dep in data.get("dependencies", []):
            name, version = dep.get("name"), dep.get("version")
            for v in dep.get("vulns", []):
                f = Finding(
                    plugin="sca", category="sca",
                    title=f"{name}@{version}: {v.get('id')}",
                    severity=Severity.from_any(v.get("severity", "MEDIUM")),
                    confidence=Confidence.STRONG,
                    cwe=_cwe_from_aliases(v.get("aliases", [])),
                    remediation=f"pip install --upgrade {name}",
                    location=f"{name}@{version}",
                )
                f.add_evidence("manifest", v.get("id", ""),
                               ref=",".join(v.get("aliases", [])),
                               detail=(v.get("description") or "")[:300])
                findings.append(f)
        return findings

    @staticmethod
    def _parse_npm(text: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return findings
        for name, meta in data.get("vulnerabilities", {}).items():
            sev = SEV_MAP.get((meta.get("severity") or "").upper(), "MEDIUM")
            via = meta.get("via", [])
            for v in via:
                if isinstance(v, dict):
                    f = Finding(
                        plugin="sca", category="sca",
                        title=f"{name}: {v.get('title', 'npm advisory')}",
                        severity=Severity.from_any(sev),
                        confidence=Confidence.STRONG,
                        cwe=_cwe_from_aliases(
                            [f"CVE-{v['cve']}"] if v.get("cve") else []),
                        remediation=f"npm audit fix; upgrade {name}",
                        location=name,
                    )
                    f.add_evidence("manifest", v.get("url", ""),
                                   ref=v.get("url", "") or name,
                                   detail=v.get("range", ""))
                    findings.append(f)
        return findings

    async def _collect_manifests(self, root: Path) -> list[dict]:

        specs: list[dict] = []
        for fname in ("requirements.txt", "package.json"):
            p = root / fname
            if not p.exists():
                continue
            eco = _ECOSYSTEM[fname]
            if fname == "requirements.txt":
                for line in p.read_text(errors="ignore").splitlines():
                    line = line.strip()
                    if not line or line.startswith(("#", "-")):
                        continue
                    m = _SPEC_RE.search(line)
                    if m:
                        specs.append({"name": m.group(1),
                                      "version": m.group(2), "eco": eco,
                                      "source": str(p)})
            else:
                try:
                    data = json.loads(p.read_text(errors="ignore"))
                except json.JSONDecodeError:
                    continue
                for name, vspec in (data.get("dependencies") or {}).items():
                    versions = re.findall(r"[0-9][A-Za-z0-9._-]*", str(vspec))
                    if versions:
                        specs.append({"name": name, "version": versions[-1],
                                      "eco": eco, "source": str(p)})
        return specs

    async def _osv_query(self, specs: list[dict]) -> list[Finding]:

        findings: list[Finding] = []
        if not specs:
            return findings
        batch = {"queries": [
            {"package": {"name": s["name"], "ecosystem": s["eco"]},
             "version": s["version"]} for s in specs]}
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.post("https://api.osv.dev/v1/querybatch", json=batch)
                r.raise_for_status()
                data = r.json()
        except Exception as exc:
            log.warning("sca_osv_query_failed", error=str(exc))
            return findings


        for idx, result in enumerate(data.get("results", [])):
            vulns = result.get("vulns", [])
            if not vulns:
                continue
            spec = specs[idx]
            pkg_name = spec["name"]
            version = spec["version"]
            source_file = spec["source"]
            for vuln in vulns:
                aliases = [a for a in vuln.get("aliases", [])
                           if a.upper().startswith("CVE-")
                           or a.upper().startswith("GHSA-")]
                f = Finding(
                    plugin="sca", category="sca",
                    title=f"{pkg_name}@{version}: {vuln.get('id', 'unknown advisory')}",
                    severity=Severity.from_any(vuln.get("severity", "MEDIUM")),
                    confidence=Confidence.STRONG,
                    cwe=_cwe_from_aliases(aliases),
                    remediation=f"Upgrade {pkg_name} to patch vulnerability {vuln.get('id')}",
                    location=f"{os.path.basename(source_file)}:{pkg_name}@{version}",
                    target=pkg_name,
                )
                f.add_evidence(
                    kind="manifest",
                    detail=vuln.get("summary", vuln.get("details", "")[:120]),
                    ref=",".join(aliases) or pkg_name,
                )
                findings.append(f)
        return findings
