
from __future__ import annotations

import argparse
import asyncio
import os
import re
import sys
from datetime import datetime

from kelan.dast.pipeline import ScanOptions, run_scan, render_report

DEFAULT_VECTORS = "xss,sqli,cmdi,traversal,ssti"


def resolve_report_path(raw_path: str, target: str = "") -> str:

    os.makedirs("reports", exist_ok=True)
    if not raw_path:
        slug = re.sub(r"[^a-zA-Z0-9_\-]", "_", target.replace("https://", "").replace("http://", ""))[:30].strip("_")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"dast_{slug}_{ts}.json" if slug else f"dast_{ts}.json"
        return os.path.join("reports", filename)
    if not os.path.dirname(raw_path):
        return os.path.join("reports", raw_path)
    return raw_path


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="kelan dast", description="Kelan DAST agent")
    p.add_argument("--target", required=True, help="seed URL")
    p.add_argument("--model", default="qwen2.5-coder:latest")
    p.add_argument("--endpoint", default="http://127.0.0.1:11434")
    p.add_argument("--crawl", action="store_true",
                   help="spider links from the seed page before probing")
    p.add_argument("--max-pages", type=int, default=15)
    p.add_argument("--max-depth", type=int, default=3)
    p.add_argument("--delay", type=float, default=0.5,
                   help="politeness delay between requests (seconds)")
    p.add_argument("--bypass", action="store_true",
                   help="add encoding/obfuscation variants (WAF / ValidateRequest bypass attempts)")
    p.add_argument("--vectors", default=DEFAULT_VECTORS,
                   help=f"comma list of vectors (default: {DEFAULT_VECTORS})")
    p.add_argument("--json", dest="json_out", nargs="?", const="",
                   help="write findings to JSON file")
    p.add_argument("--ci-gate", choices=["critical", "high", "medium", "low"],
                   help="exit 1 if any finding at/above this severity")
    p.add_argument("--concurrency", type=int, default=2)
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--fuzz-tokens", action="store_true",
                   help="also fuzz CSRF tokens / __VIEWSTATE-style fields")
    p.add_argument("--external", action="store_true",
                   help="allow crawling links off the seed host")
    p.add_argument("--no-llm", action="store_true",
                   help="skip Ollama summarization (deterministic only)")
    args = p.parse_args(argv)

    print("🕵️  Kelan DAST Agent")
    print(f"   Target:  {args.target}")
    print(f"   Model:   {args.model}")
    if args.crawl:
        print(f"   Crawl:   on (max {args.max_pages} pages, depth {args.max_depth})")
    if args.bypass:
        print("   Bypass probes: on (encoding variants)")

    opts = ScanOptions(
        target=args.target, model=args.model, endpoint=args.endpoint,
        crawl=args.crawl, max_pages=args.max_pages, max_depth=args.max_depth,
        delay=args.delay, bypass=args.bypass,
        vectors=tuple(v.strip().lower() for v in args.vectors.split(",") if v.strip()),
        timeout=args.timeout, concurrency=args.concurrency,
        fuzz_tokens=args.fuzz_tokens, external=args.external,
        use_llm=not args.no_llm,
    )
    if opts.use_llm:
        print("🧠  Evaluating with local Ollama engine…")

    try:
        report = asyncio.run(run_scan(opts))
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"[!] scan failed: {exc}", file=sys.stderr)
        return 2

    render_report(report)
    if args.json_out is not None:
        json_path = resolve_report_path(args.json_out, args.target)
        report.write_json(json_path)
        print(f"\n📄 wrote {json_path}")
    if args.ci_gate:
        code = report.gate(args.ci_gate)
        print(f"🧪 CI gate ({args.ci_gate}): {'FAIL' if code else 'PASS'}")
        return code
    return 0


if __name__ == "__main__":
    sys.exit(main())
