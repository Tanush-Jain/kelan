from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import sys
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, cast

import httpx
import structlog

from kelan.core.finding import Confidence, Finding, Severity
from kelan.core.plugin import PluginResult, ScanContext, ScanPlugin, ScopeKind
from kelan.intel.db import IntelStore
from kelan.intel.models import PackageSpec

log = structlog.get_logger()

SEV_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MODERATE": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
}

_ECOSYSTEM = {
    "requirements.txt": "PyPI",
    "Pipfile": "PyPI",
    "Pipfile.lock": "PyPI",
    "poetry.lock": "PyPI",
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "Cargo.lock": "crates.io",
    "Cargo.toml": "crates.io",
    "go.mod": "Go",
    "go.sum": "Go",
    "pom.xml": "Maven",
    "build.gradle": "Maven",
    "build.gradle.kts": "Maven",
    "default.lock": "Maven",
}

_SPEC_RE = re.compile(r"([A-Za-z0-9_.-]+)[\s===]+([0-9][A-Za-z0-9._-]*)")


def _cwe_from_aliases(aliases: list[str]) -> str:
    return "CWE-1035"


class ScaPlugin(ScanPlugin):
    name = "sca"
    version = "0.2"
    description = "Software composition analysis: Offline Intel Store + OSV / Lockfile scanner"
    applies_to = {ScopeKind.REPO, ScopeKind.CODEBASE}

    async def run(self, ctx: ScanContext) -> PluginResult:
        root = Path(ctx.target.value) if ctx.target.kind == ScopeKind.CODEBASE else ctx.workspace / "repo"
        pr = PluginResult(plugin=self.name)

        # 1. External tool execution if locally installed (osv-scanner, pip-audit, npm audit)
        for tool, args in (
            ("osv-scanner", ["--json"]),
            ("pip-audit", ["--format", "json"]),
            ("npm", ["audit", "--json"]),
        ):
            if shutil.which(tool):
                try:
                    pr.findings.extend(await self._run_tool(tool, args, root))
                except Exception as exc:
                    pr.errors.append(f"{tool}: {exc}")

        # 2. Collect dependencies from lockfiles and manifests
        specs = await self._collect_manifests(root)

        # 3. Local-first Intelligence Store matching
        db_path = ctx.config.get("intel_db") or os.getenv("KELAN_INTEL_DB")
        max_age_days = int(ctx.config.get("max_intel_age_days") or os.getenv("KELAN_MAX_INTEL_AGE_DAYS", "7"))

        try:
            store = IntelStore(db_path)
            staleness = store.get_staleness_info(max_age_days=max_age_days)
            last_updated_str = staleness["last_updated"] or "never"
            pr.meta["intel_last_updated"] = last_updated_str
            pr.meta["intel_is_stale"] = staleness["is_stale"]

            # Staleness warning
            if staleness["is_stale"]:
                warn_msg = (
                    f"Local vulnerability intelligence is stale or uninitialized "
                    f"(last sync: {last_updated_str}, threshold: {max_age_days} days). "
                    f"Run 'kelan update' or import an offline bundle with 'kelan update --offline-bundle FILE'."
                )
                pr.meta["staleness_warning"] = warn_msg
                log.warning("sca_intel_store_stale", last_updated=last_updated_str, max_age_days=max_age_days)

            if specs:
                # Record scanned packages for trending correlation
                pkg_specs = [
                    PackageSpec(
                        name=s["name"],
                        version=s["version"],
                        ecosystem=s["eco"],
                        source=s.get("source", ""),
                    )
                    for s in specs
                ]
                store.record_scanned_packages(pkg_specs)

                # Match packages against local intelligence store
                local_matches = store.match_packages(pkg_specs)
                for spec, adv in local_matches:
                    sev = adv.severity or "MEDIUM"
                    finding = Finding(
                        plugin=self.name,
                        category="sca",
                        title=f"{spec.name}@{spec.version}: {adv.id}",
                        severity=Severity.from_any(sev),
                        confidence=Confidence.STRONG,
                        cwe=_cwe_from_aliases(adv.aliases),
                        remediation=f"Upgrade {spec.name} (affects {spec.version}).",
                        location=f"{os.path.basename(spec.source) if spec.source else 'manifest'}:{spec.name}@{spec.version}",
                        target=spec.name,
                    )
                    # Add detailed evidence with provenance, EPSS, and KEV
                    evidence_detail = adv.title or adv.description or adv.id
                    extra_meta = {
                        "advisory_id": adv.id,
                        "source": adv.source,
                        "epss_score": adv.epss_score,
                        "epss_percentile": adv.epss_percentile,
                        "is_kev": adv.is_kev,
                        "kev_date_added": adv.kev_date_added,
                        "cvss_score": adv.cvss_score,
                        "cvss_vector": adv.cvss_vector,
                        "aliases": adv.aliases,
                    }
                    finding.add_evidence(
                        kind="manifest",
                        detail=evidence_detail[:300],
                        ref=",".join(adv.aliases) or adv.id,
                        **cast(dict[str, Any], extra_meta),
                    )
                    pr.findings.append(finding)

            store.close()
        except Exception as exc:
            log.warning("sca_local_intel_error", error=str(exc))
            pr.errors.append(f"Local intel store error: {exc}")

        # 4. Online live query opt-in
        allow_network = bool(
            ctx.config.get("allow_network", False)
            or ctx.config.get("online", False)
            or ctx.config.section(self.name).get("allow_network", False)
            or ctx.config.section(self.name).get("online", False)
        )

        if not allow_network:
            pr.meta["network_call"] = "disabled"
            pr.meta["notice"] = (
                "Local-first active: external query to api.osv.dev skipped. "
                "Enable with --allow-network or --online, or update local intelligence with 'kelan update'."
            )
        else:
            if not shutil.which("osv-scanner") and not shutil.which("pip-audit") and not shutil.which("npm"):
                if specs:
                    print(
                        f"[Notice] Network call enabled: querying api.osv.dev for {len(specs)} dependencies...",
                        file=sys.stderr,
                    )
                    pr.meta["network_call"] = "enabled (api.osv.dev)"
                    try:
                        live_findings = await self._osv_query(specs)
                        existing_keys = {f.key() for f in pr.findings}
                        for lf in live_findings:
                            if lf.key() not in existing_keys:
                                pr.findings.append(lf)
                    except Exception as exc:
                        pr.errors.append(f"OSV query error: {exc}")

        return pr

    async def _run_tool(self, tool: str, args: list[str], root: Path) -> list[Finding]:
        proc = await asyncio.create_subprocess_exec(
            tool,
            *args,
            cwd=str(root),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
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
                    aliases = [
                        a
                        for a in vuln.get("aliases", [])
                        if a.upper().startswith("CVE-") or a.upper().startswith("GHSA-")
                    ]
                    f = Finding(
                        plugin="sca",
                        category="sca",
                        title=f"{pkg_name}@{version}: {vuln.get('id', 'unknown advisory')}",
                        severity=Severity.from_any(vuln.get("severity", "MEDIUM")),
                        confidence=Confidence.STRONG,
                        cwe=_cwe_from_aliases(aliases),
                        remediation=f"Upgrade {pkg_name} (affects {version}).",
                        location=f"{loc}:{pkg_name}@{version}",
                        target=str(root),
                    )
                    f.add_evidence(
                        "manifest",
                        vuln.get("summary", "") or vuln.get("id", ""),
                        ref=",".join(aliases) or pkg_name,
                    )
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
                    plugin="sca",
                    category="sca",
                    title=f"{name}@{version}: {v.get('id')}",
                    severity=Severity.from_any(v.get("severity", "MEDIUM")),
                    confidence=Confidence.STRONG,
                    cwe=_cwe_from_aliases(v.get("aliases", [])),
                    remediation=f"pip install --upgrade {name}",
                    location=f"{name}@{version}",
                )
                f.add_evidence(
                    "manifest",
                    (v.get("description") or "")[:300] or v.get("id", ""),
                    ref=",".join(v.get("aliases", [])),
                )
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
                        plugin="sca",
                        category="sca",
                        title=f"{name}: {v.get('title', 'npm advisory')}",
                        severity=Severity.from_any(sev),
                        confidence=Confidence.STRONG,
                        cwe=_cwe_from_aliases([f"CVE-{v['cve']}"] if v.get("cve") else []),
                        remediation=f"npm audit fix; upgrade {name}",
                        location=name,
                    )
                    f.add_evidence(
                        "manifest",
                        v.get("range", "") or v.get("url", ""),
                        ref=v.get("url", "") or name,
                    )
                    findings.append(f)
        return findings

    async def _collect_manifests(self, root: Path) -> list[dict]:
        specs: list[dict] = []

        # 1. requirements.txt
        req_p = root / "requirements.txt"
        if req_p.exists():
            for line in req_p.read_text(errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith(("#", "-", "@")):
                    continue
                m = _SPEC_RE.search(line)
                if m:
                    specs.append({
                        "name": m.group(1),
                        "version": m.group(2),
                        "eco": "PyPI",
                        "source": str(req_p),
                    })

        # 2. Pipfile.lock
        pipfile_lock = root / "Pipfile.lock"
        if pipfile_lock.exists():
            try:
                data = json.loads(pipfile_lock.read_text(errors="ignore"))
                for section in ("default", "develop"):
                    for pkg_name, meta in data.get(section, {}).items():
                        v_str = meta.get("version", "")
                        clean_v = v_str.lstrip("=").strip()
                        if clean_v:
                            specs.append({
                                "name": pkg_name,
                                "version": clean_v,
                                "eco": "PyPI",
                                "source": str(pipfile_lock),
                            })
            except Exception:
                pass

        # 3. poetry.lock
        poetry_lock = root / "poetry.lock"
        if poetry_lock.exists():
            try:
                data = tomllib.loads(poetry_lock.read_text(errors="ignore"))
                for pkg in data.get("package", []):
                    name = pkg.get("name")
                    ver = pkg.get("version")
                    if name and ver:
                        specs.append({
                            "name": name,
                            "version": ver,
                            "eco": "PyPI",
                            "source": str(poetry_lock),
                        })
            except Exception:
                pass

        # 4. package.json
        pkg_json = root / "package.json"
        if pkg_json.exists():
            try:
                data = json.loads(pkg_json.read_text(errors="ignore"))
                combined_deps = {}
                combined_deps.update(data.get("dependencies") or {})
                combined_deps.update(data.get("devDependencies") or {})
                for name, vspec in combined_deps.items():
                    versions = re.findall(r"[0-9][A-Za-z0-9._-]*", str(vspec))
                    if versions:
                        specs.append({
                            "name": name,
                            "version": versions[-1],
                            "eco": "npm",
                            "source": str(pkg_json),
                        })
            except Exception:
                pass

        # 5. package-lock.json
        pkg_lock = root / "package-lock.json"
        if pkg_lock.exists():
            try:
                data = json.loads(pkg_lock.read_text(errors="ignore"))
                packages = data.get("packages", {})
                for pkg_key, meta in packages.items():
                    if not pkg_key or not isinstance(meta, dict):
                        continue
                    name = meta.get("name")
                    if not name and "node_modules/" in pkg_key:
                        name = pkg_key.split("node_modules/")[-1]
                    ver = meta.get("version")
                    if name and ver:
                        specs.append({
                            "name": name,
                            "version": ver,
                            "eco": "npm",
                            "source": str(pkg_lock),
                        })
                if not packages:
                    for dep_name, meta in data.get("dependencies", {}).items():
                        ver = meta.get("version")
                        if dep_name and ver:
                            specs.append({
                                "name": dep_name,
                                "version": ver,
                                "eco": "npm",
                                "source": str(pkg_lock),
                            })
            except Exception:
                pass

        # 6. yarn.lock
        yarn_lock = root / "yarn.lock"
        if yarn_lock.exists():
            try:
                lines = yarn_lock.read_text(errors="ignore").splitlines()
                current_pkg: str | None = None
                for line in lines:
                    line_s = line.strip()
                    if line_s.endswith(":") and not line.startswith(" "):
                        parts = line_s[:-1].split(",")
                        if parts:
                            raw = parts[0].strip().strip('"').strip("'")
                            if "@" in raw:
                                current_pkg = raw.split("@")[0] if not raw.startswith("@") else "@" + raw[1:].split("@")[0]
                    elif line_s.startswith("version ") and current_pkg:
                        v = line_s.split("version ")[1].strip().strip('"').strip("'")
                        specs.append({
                            "name": current_pkg,
                            "version": v,
                            "eco": "npm",
                            "source": str(yarn_lock),
                        })
                        current_pkg = None
            except Exception:
                pass

        # 7. pnpm-lock.yaml
        pnpm_lock = root / "pnpm-lock.yaml"
        if pnpm_lock.exists():
            try:
                for line in pnpm_lock.read_text(errors="ignore").splitlines():
                    line_s = line.strip()
                    m = re.match(r"^['\"]?/?([@A-Za-z0-9_.-]+)@([0-9][A-Za-z0-9._-]*)['\"]?:", line_s)
                    if m:
                        specs.append({
                            "name": m.group(1),
                            "version": m.group(2),
                            "eco": "npm",
                            "source": str(pnpm_lock),
                        })
            except Exception:
                pass

        # 8. Cargo.lock
        cargo_lock = root / "Cargo.lock"
        if cargo_lock.exists():
            try:
                data = tomllib.loads(cargo_lock.read_text(errors="ignore"))
                for pkg in data.get("package", []):
                    name = pkg.get("name")
                    ver = pkg.get("version")
                    if name and ver:
                        specs.append({
                            "name": name,
                            "version": ver,
                            "eco": "crates.io",
                            "source": str(cargo_lock),
                        })
            except Exception:
                pass

        # 9. Cargo.toml
        cargo_toml = root / "Cargo.toml"
        if cargo_toml.exists():
            try:
                data = tomllib.loads(cargo_toml.read_text(errors="ignore"))
                for dep_sec in ("dependencies", "dev-dependencies"):
                    for name, vspec in data.get(dep_sec, {}).items():
                        v_str = vspec if isinstance(vspec, str) else vspec.get("version", "") if isinstance(vspec, dict) else ""
                        m = re.search(r"[0-9][A-Za-z0-9._-]*", str(v_str))
                        if m:
                            specs.append({
                                "name": name,
                                "version": m.group(0),
                                "eco": "crates.io",
                                "source": str(cargo_toml),
                            })
            except Exception:
                pass

        # 10. go.mod
        go_mod = root / "go.mod"
        if go_mod.exists():
            try:
                in_require = False
                for line in go_mod.read_text(errors="ignore").splitlines():
                    line_s = line.strip()
                    if line_s == "require (":
                        in_require = True
                        continue
                    if in_require and line_s == ")":
                        in_require = False
                        continue
                    if in_require or line_s.startswith("require "):
                        parts = line_s.removeprefix("require ").strip().split()
                        if len(parts) >= 2:
                            specs.append({
                                "name": parts[0],
                                "version": parts[1].lstrip("v"),
                                "eco": "Go",
                                "source": str(go_mod),
                            })
            except Exception:
                pass

        # 11. go.sum
        go_sum = root / "go.sum"
        if go_sum.exists():
            try:
                for line in go_sum.read_text(errors="ignore").splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        name = parts[0]
                        v = parts[1].split("/go.mod")[0].lstrip("v")
                        specs.append({
                            "name": name,
                            "version": v,
                            "eco": "Go",
                            "source": str(go_sum),
                        })
            except Exception:
                pass

        # 12. pom.xml
        pom_xml = root / "pom.xml"
        if pom_xml.exists():
            try:
                tree = ET.fromstring(pom_xml.read_text(errors="ignore"))
                for dep in tree.findall(".//{*}dependency"):
                    art = dep.find("{*}artifactId")
                    ver = dep.find("{*}version")
                    if art is not None and art.text and ver is not None and ver.text:
                        clean_ver = ver.text.strip()
                        if not clean_ver.startswith("${"):
                            specs.append({
                                "name": art.text.strip(),
                                "version": clean_ver,
                                "eco": "Maven",
                                "source": str(pom_xml),
                            })
            except Exception:
                pass

        # 13. build.gradle
        for gradle_name in ("build.gradle", "build.gradle.kts"):
            gradle_p = root / gradle_name
            if gradle_p.exists():
                try:
                    for line in gradle_p.read_text(errors="ignore").splitlines():
                        m = re.search(r"['\"]([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([0-9][A-Za-z0-9._-]*)['\"]", line)
                        if m:
                            specs.append({
                                "name": m.group(2),
                                "version": m.group(3),
                                "eco": "Maven",
                                "source": str(gradle_p),
                            })
                except Exception:
                    pass

        # Deduplicate specs by (eco, name, version)
        seen = set()
        deduped = []
        for s in specs:
            k = (s["eco"].lower(), s["name"].lower(), s["version"])
            if k not in seen:
                seen.add(k)
                deduped.append(s)

        return deduped

    async def _osv_query(self, specs: list[dict]) -> list[Finding]:
        findings: list[Finding] = []
        if not specs:
            return findings
        batch = {
            "queries": [
                {
                    "package": {"name": s["name"], "ecosystem": s["eco"]},
                    "version": s["version"],
                }
                for s in specs
            ]
        }
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.post("https://api.osv.dev/v1/querybatch", json=batch)
                r.raise_for_status()
                data = r.json()
        except Exception as exc:
            log.warning("sca_osv_query_failed", error=str(exc))
            raise

        for idx, result in enumerate(data.get("results", [])):
            vulns = result.get("vulns", [])
            if not vulns:
                continue
            spec = specs[idx]
            pkg_name = spec["name"]
            version = spec["version"]
            source_file = spec.get("source", "manifest")
            for vuln in vulns:
                aliases = [
                    a
                    for a in vuln.get("aliases", [])
                    if a.upper().startswith("CVE-") or a.upper().startswith("GHSA-")
                ]
                f = Finding(
                    plugin="sca",
                    category="sca",
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
