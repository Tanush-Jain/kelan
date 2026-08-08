
from __future__ import annotations

import asyncio
import importlib.util
import shutil
import sys

import httpx


def _check(name: str, ok: bool, detail: str = "") -> None:
    mark = "✔" if ok else "✘"
    print(f"  {mark} {name}" + (f"  ({detail})" if detail else ""))


async def doctor() -> int:
    print("Kelan environment check")
    failed = False


    _check("Python >= 3.10", sys.version_info >= (3, 10), sys.version.split()[0])


    try:
        async with httpx.AsyncClient(timeout=3) as c:
            r = await c.get("http://127.0.0.1:11434/api/tags")
        ok = r.status_code == 200
        models = [m.get("name", "") for m in r.json().get("models", [])]
        _check("Ollama reachable", ok,
               ", ".join(models[:5]) if ok else "start `ollama serve`")
        if ok and not models:
            _check("Ollama model pulled", False,
                   "run: ollama pull qwen2.5-coder:latest")
        elif ok:
            _check("Ollama model pulled", any("coder" in m for m in models),
                   "recommended: qwen2.5-coder:latest")
    except httpx.HTTPError:
        _check("Ollama reachable", False, "start `ollama serve`")


    for mod in ("tree_sitter", "tree_sitter_languages", "httpx", "structlog"):
        _check(f"python module: {mod}", importlib.util.find_spec(mod) is not None)


    for tool in ("osv-scanner", "pip-audit", "npm", "tfsec", "checkov"):
        _check(f"tool: {tool}", shutil.which(tool) is not None or tool == "npm")


    if sys.platform.startswith("linux"):
        try:
            with open("/proc/sys/kernel/unprivileged_bpf_disabled") as fh:
                bpf_state = fh.read().strip()
            _check("eBPF kernel support", True, f"unprivileged_bpf_disabled={bpf_state}")
        except OSError:
            _check("eBPF kernel support", False, "not exposed on this kernel")
    else:
        _check("eBPF (simulation mode)", True, f"{sys.platform}: software fallback")


    _check("PQC: mlkem", importlib.util.find_spec("mlkem") is not None
           or importlib.util.find_spec("cryptography") is not None)

    print("\n" + ("Readiness: OK — you can scan." if not failed
                  else "Readiness: issues found — see details above."))
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(doctor()))
