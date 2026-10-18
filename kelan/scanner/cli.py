"""Kelan scanner CLI — chunk → Ollama SAST analysis → structured report."""
import argparse
import asyncio
import json
import os
import sys
import urllib.request
from typing import Optional

from kelan.scanner.analyzer import VulnerabilityAnalyzer
from kelan.scanner.chunker import SemanticChunker

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
IGNORE_DIRS = {".git", "node_modules", "venv", ".venv", "target",
               "dist", "build", "__pycache__"}
SCAN_EXTS = {".py", ".js", ".ts", ".tsx"}
DEFAULT_MODEL = "qwen2.5-coder:latest"
DEFAULT_ENDPOINT = "http://127.0.0.1:11434"


# ──────────────────────────────────────────────────────────────────────────────
# Ollama helpers
# ──────────────────────────────────────────────────────────────────────────────

def get_local_models() -> list[str]:
    """Fetch available models from the local Ollama instance."""
    try:
        req = urllib.request.Request(f"{DEFAULT_ENDPOINT}/api/tags")
        with urllib.request.urlopen(req, timeout=2) as resp:  # nosec B310
            data = json.loads(resp.read().decode())
            return [m["name"] for m in data.get("models", [])]
    except Exception:
        return []


# ──────────────────────────────────────────────────────────────────────────────
# Core pipeline
# ──────────────────────────────────────────────────────────────────────────────

def collect_chunks(target: str, limit: Optional[int]) -> list:
    chunker = SemanticChunker()
    chunks = []
    for root, dirs, files in os.walk(target):
        dirs[:] = sorted(d for d in dirs if d not in IGNORE_DIRS)
        for file in sorted(files):
            if os.path.splitext(file)[1].lower() not in SCAN_EXTS:
                continue
            path = os.path.join(root, file)
            try:
                with open(path, "rb") as fh:
                    code = fh.read()
                for chunk in chunker.extract_chunks(path, code):
                    chunks.append(chunk)
                    if limit and len(chunks) >= limit:
                        return chunks
            except Exception as exc:
                print(f"[!] skip {path}: {exc}", file=sys.stderr)
    return chunks


async def analyze_all(chunks, endpoint, model, concurrency, timeout):
    analyzer = VulnerabilityAnalyzer(
        endpoint=endpoint, model=model, timeout=timeout
    )
    sem = asyncio.Semaphore(concurrency)

    async def one(chunk):
        async with sem:
            result = await analyzer.analyze_chunk(chunk)
            return {**chunk, "analysis": result}

    try:
        return await asyncio.gather(*[one(c) for c in chunks])
    finally:
        await analyzer.close()


def render_report(results, target) -> list:
    flagged = [r for r in results if r["analysis"]["has_security_flaw"]]
    for r in flagged:
        r["analysis"]["findings"].sort(
            key=lambda f: SEV_ORDER.get(f["severity"], 9)
        )
    flagged.sort(key=lambda r: (
        SEV_ORDER.get(r["analysis"]["findings"][0]["severity"], 9),
        r["file_path"], r["start_line"],
    ))

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in flagged:
        for f in r["analysis"]["findings"]:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    width = 72
    print("=" * width)
    print("KELAN SCAN — SAST REPORT")
    print("=" * width)
    print(f"Target:          {os.path.abspath(target)}")
    print(f"Chunks analyzed: {len(results)}  |  Flagged: {len(flagged)}")
    print(f"Findings:        CRITICAL={counts['CRITICAL']}  HIGH={counts['HIGH']}  "
          f"MEDIUM={counts['MEDIUM']}  LOW={counts['LOW']}")
    print("=" * width)

    for r in flagged:
        rel = os.path.relpath(r["file_path"], target)
        line_range = f"{r['start_line'] + 1}-{r['end_line'] + 1}"
        print(f"\n[{r['analysis']['findings'][0]['severity']}] {rel}  lines {line_range}")
        for f in r["analysis"]["findings"]:
            print(f"  CWE:       {f['cwe_id']}")
            print(f"  Severity:  {f['severity']}")
            print(f"  Title:     {f['title']}")
            print(f"  Root cause:\n    {f['root_cause_analysis']}")
            print(f"  Remediation:\n    {f['remediation']}")
        print("-" * width)

    if not flagged:
        print("\n✅ No security flaws detected in audited chunks.")

    print("=" * width)
    print(f"Done: {len(results)} chunks, {len(flagged)} flagged.")
    print("=" * width)
    return flagged


# ──────────────────────────────────────────────────────────────────────────────
# Async entry point (called by main after interactive setup)
# ──────────────────────────────────────────────────────────────────────────────

async def main_async(target: str, limit: int, model: str,
                     endpoint: str = DEFAULT_ENDPOINT,
                     concurrency: int = 2, timeout: float = 180.0,
                     json_out: Optional[str] = None) -> int:
    if not os.path.isdir(target):
        print(f"[!] target not a directory: {target}", file=sys.stderr)
        return 2

    effective_limit = None if limit == 0 else max(0, limit)
    print(f"\n🔍 Scanning target: {os.path.abspath(target)}")
    print(f"   Model:     {model}")
    print(f"   Limit:     {'all chunks' if not effective_limit else effective_limit}")
    print(f"   Workers:   {concurrency}\n")

    chunks = collect_chunks(target, effective_limit)
    print(f"[*] {len(chunks)} chunk(s) to analyze with {model}")

    if not chunks:
        print("No chunks found.")
        return 0

    results = await analyze_all(chunks, endpoint, model, concurrency, timeout)
    render_report(results, target)

    if json_out:
        with open(json_out, "w") as fh:
            json.dump(results, fh, indent=2)
        print(f"[*] wrote {json_out}")

    return 0


# ──────────────────────────────────────────────────────────────────────────────
# Interactive CLI entry point
# ──────────────────────────────────────────────────────────────────────────────

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Kelan Scan — AI-native SAST scanner")
    parser.add_argument("--target",      help="Target directory (prompts if missing)")
    parser.add_argument("--limit",       type=int, help="Max chunks (0 for all, prompts if missing)")
    parser.add_argument("--model",       help="Ollama model name (prompts if missing)")
    parser.add_argument("--endpoint",    default=DEFAULT_ENDPOINT, help="Ollama endpoint")
    parser.add_argument("--concurrency", type=int, default=2, help="Parallel workers")
    parser.add_argument("--timeout",     type=float, default=180.0, help="Per-chunk timeout (s)")
    parser.add_argument("--json",        dest="json_out", help="Write results to JSON file")
    parser.add_argument("--no-limit",    action="store_true", help="Analyze all chunks")
    args = parser.parse_args(argv)

    # ── 1. Target ──────────────────────────────────────────────────────────────
    if not args.target:
        raw = input("🎯 Enter target directory to scan [default: .]: ").strip()
        args.target = raw or "."

    # ── 2. Limit ───────────────────────────────────────────────────────────────
    if args.limit is None and not args.no_limit:
        raw = input("⚡ Enter chunk limit (0 for all) [default: 10]: ").strip()
        args.limit = int(raw) if raw.isdigit() else 10

    # ── 3. Model ───────────────────────────────────────────────────────────────
    if not args.model:
        models = get_local_models()
        if models:
            print("\n🧠 Available local models:")
            for i, m in enumerate(models, 1):
                tag = "  ← recommended" if "coder" in m else ""
                print(f"  {i}. {m}{tag}")
            choice = input(
                f"\nSelect a model (1–{len(models)}) or type name "
                f"[default: {DEFAULT_MODEL}]: "
            ).strip()
            if choice.isdigit() and 1 <= int(choice) <= len(models):
                args.model = models[int(choice) - 1]
            else:
                args.model = choice or DEFAULT_MODEL
        else:
            print("\n⚠️  Could not connect to Ollama to list models.")
            choice = input(f"Enter model name [default: {DEFAULT_MODEL}]: ").strip()
            args.model = choice or DEFAULT_MODEL

    print("\n" + "─" * 40)

    limit = 0 if args.no_limit else (args.limit or 10)
    return asyncio.run(main_async(
        target=args.target,
        limit=limit,
        model=args.model,
        endpoint=args.endpoint,
        concurrency=args.concurrency,
        timeout=args.timeout,
        json_out=args.json_out,
    ))


if __name__ == "__main__":
    sys.exit(main())
