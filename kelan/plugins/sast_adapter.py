
from __future__ import annotations

from pathlib import Path

from kelan.core.finding import Confidence, Finding, Severity
from kelan.core.plugin import PluginResult, ScanContext, ScanPlugin, ScopeKind


class SastPlugin(ScanPlugin):
    name = "sast"
    version = "0.2"
    description = "Static analysis of source chunks via chunker + Ollama analyzer"
    applies_to = {ScopeKind.CODEBASE, ScopeKind.REPO}

    async def run(self, ctx: ScanContext) -> PluginResult:
        import asyncio

        target_path = (ctx.target.value if ctx.target.kind == ScopeKind.CODEBASE
                       else None)
        if ctx.target.kind == ScopeKind.REPO:
            repo = ctx.target.value
            clone_dir = ctx.workspace / "repo"
            proc = await asyncio.create_subprocess_exec(
                "git", "clone", "--depth", "1", repo, str(clone_dir),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL)
            await proc.wait()
            if proc.returncode != 0:
                return PluginResult(self.name, errors=[f"git clone failed: {repo}"])
            target_path = str(clone_dir)

        from kelan.scanner.chunker import SemanticChunker
        from kelan.scanner.analyzer import VulnerabilityAnalyzer

        root = Path(target_path)
        excludes = set(ctx.config.section("sast").get(
            "exclude", (".git", "node_modules", "venv", ".venv", "target")))

        analyzer = VulnerabilityAnalyzer(
            endpoint=(ctx.ollama or {}).get(
                "endpoint", "http://127.0.0.1:11434"),
            model=(ctx.ollama or {}).get("model", "qwen2.5-coder:latest"))

        pr = PluginResult(plugin=self.name)
        n_files = n_chunks = 0

        async def analyze_file(path: Path) -> list[Finding]:
            nonlocal n_files, n_chunks
            try:

                with open(path, "rb") as fh:
                    code = fh.read()

                from kelan.scanner.chunker import SemanticChunker
                chunker = SemanticChunker()
                chunks = list(chunker.extract_chunks(str(path), code))
                if not chunks:
                    chunks = [{
                        "file_path": str(path),
                        "type": "module",
                        "start_line": 1,
                        "end_line": len(code.splitlines()) or 1,
                        "content": code.decode("utf-8", errors="replace"),
                    }]
            except Exception as e:
                import sys
                print(f"Exception scanning {path}: {e}", file=sys.stderr)
                return []
            n_files += 1
            n_chunks += len(chunks)
            findings: list[Finding] = []
            for chunk in chunks:
                verdict = await analyzer.analyze_chunk(chunk)
                if verdict.get("has_security_flaw"):
                    f = Finding(
                        plugin="sast",
                        category="sast",
                        title=verdict.get("findings", [{}])[0].get(
                            "title", "SAST finding")
                        if verdict.get("findings") else "SAST finding",
                        severity=Severity.from_any(
                            verdict.get("findings", [{}])[0].get(
                                "severity", "MEDIUM"))
                        if verdict.get("findings") else Severity.MEDIUM,
                        cwe=verdict.get("findings", [{}])[0].get("cwe", "CWE-710")
                        if verdict.get("findings") else "CWE-710",
                        remediation=verdict.get("findings", [{}])[0].get(
                            "remediation", "") if verdict.get("findings") else "",
                        location=f"{path}:{chunk.get('start_line', 1)}",
                        target=str(path),
                    )
                    f.add_evidence("advisory",
                                   verdict.get("findings", [{}])[0].get(
                                       "description", ""),
                                   ref=f"{path}:{chunk.get('start_line', 1)}")
                    f.confidence = Confidence.MEDIUM
                    findings.append(f)
            return findings

        files = [p for p in root.rglob("*")
                 if p.is_file() and not any(part in excludes
                                            for part in p.parts)
                 and p.suffix in (".py", ".js", ".ts", ".tsx")]
        

        sem = asyncio.Semaphore(ctx.config.get("sast_concurrency", 2))

        async def guarded(path: Path):
            async with sem:
                return await analyze_file(path)

        results = await asyncio.gather(*(guarded(p) for p in files),
                                       return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                pr.errors.append(str(r))
            else:
                pr.findings.extend(r)

        pr.meta = {"files_scanned": n_files, "chunks_scanned": n_chunks}
        return pr
