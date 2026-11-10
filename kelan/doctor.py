
from __future__ import annotations

import asyncio
import importlib.util
import shutil
import sys

import httpx


def _check(name: str, ok: bool, detail: str = "", required: bool = True) -> bool:
    if ok:
        mark = "✔"
    else:
        mark = "✘" if required else "▲"
    suffix = f"  ({detail})" if detail else ""
    print(f"  {mark} {name}{suffix}")
    return ok


async def doctor() -> int:
    print("Kelan environment check")
    failed = False

    if not _check("Python >= 3.10", sys.version_info >= (3, 10), sys.version.split()[0], required=True):
        failed = True

    try:
        async with httpx.AsyncClient(timeout=3) as c:
            r = await c.get("http://127.0.0.1:11434/api/tags")
        if r.status_code == 200:
            try:
                data = r.json() if r.content else {}
            except Exception:
                data = {}
            models = [m.get("name", "") for m in data.get("models", [])]
            _check("Ollama reachable", True, ", ".join(models[:5]) if models else "no models loaded")
            if not models:
                if not _check("Ollama model pulled", False, "run: ollama pull qwen2.5-coder:latest", required=True):
                    failed = True
            else:
                has_coder = any("coder" in m for m in models)
                _check("Ollama model pulled", True, "recommended: qwen2.5-coder:latest" if not has_coder else "")
        else:
            if not _check("Ollama reachable", False, f"HTTP {r.status_code} — start `ollama serve`", required=True):
                failed = True
            if not _check("Ollama model pulled", False, "Ollama service unavailable", required=True):
                failed = True
    except Exception:
        if not _check("Ollama reachable", False, "start `ollama serve`", required=True):
            failed = True
        if not _check("Ollama model pulled", False, "Ollama service unavailable", required=True):
            failed = True

    # Verify core python modules and tree-sitter grammars from requirements.txt
    core_modules = (
        "tree_sitter",
        "tree_sitter_python",
        "tree_sitter_javascript",
        "tree_sitter_typescript",
        "httpx",
        "structlog",
    )
    for mod in core_modules:
        is_installed = importlib.util.find_spec(mod) is not None
        if not _check(f"python module: {mod}", is_installed, "run `pip install -e .`" if not is_installed else "", required=True):
            failed = True

    for tool in ("osv-scanner", "pip-audit", "npm", "tfsec", "checkov"):
        found = shutil.which(tool) is not None
        _check(f"tool: {tool}", found, "installed" if found else "optional", required=False)

    if sys.platform.startswith("linux"):
        try:
            with open("/proc/sys/kernel/unprivileged_bpf_disabled") as fh:
                bpf_state = fh.read().strip()
            _check("eBPF kernel support", True, f"unprivileged_bpf_disabled={bpf_state}", required=False)
        except OSError:
            _check("eBPF kernel support", False, "not exposed on this kernel (software fallback active)", required=False)
    else:
        _check("eBPF (simulation mode)", True, f"{sys.platform}: software fallback", required=False)

    pqc_ok = (importlib.util.find_spec("mlkem") is not None
              or importlib.util.find_spec("cryptography") is not None)
    if not _check("PQC: mlkem/cryptography", pqc_ok, required=True):
        failed = True

    print("\n" + ("Readiness: OK — you can scan." if not failed
                  else "Readiness: issues found — see details above."))
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(doctor()))
