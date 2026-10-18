












from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path

from kelan.core.finding import Confidence, Finding, Severity

EXCLUDE_DIRS = {".git", "node_modules", "venv", ".venv", "target",
                "__pycache__", "dist", "build"}
CODE_EXTS = {".py", ".js", ".ts", ".tsx", ".go", ".rb", ".java", ".php"}



_RE_CALL = re.compile(
    r"\bre\.(?:compile|match|search|fullmatch|findall|finditer|sub|subn|split)"
    r"\s*\(\s*([rubf]{0,2}['\"])")
_GROUP_WITH_QUANT = re.compile(r"\((?:[^()]*?[+*][^()]*?)\)[+*]")
_GROUP_WITH_ALT = re.compile(r"\([^()]*\|[^()]*\)[+*]")

_VALIDATE_SCRIPT = (
    "import re,sys,time\n"
    "p=sys.argv[1]; d=sys.argv[2]\n"
    "t=time.monotonic()\n"
    "try:\n"
    "    re.search(p, d)\n"
    "except Exception:\n"
    "    pass\n"
    "print(time.monotonic()-t)\n"
)


def _extract_re_patterns(text: str) -> list[tuple[int, str]]:

    out = []
    for m in _RE_CALL.finditer(text):
        quote = m.group(1)
        start = m.end()
        end = text.find(quote[-1], start)
        if end == -1:
            continue
        literal = text[start:end]
        if quote.startswith("r") or quote.startswith("b"):
            pattern = literal
        else:
            try:
                pattern = ast.literal_eval(quote[-1] + literal + quote[-1])
            except (ValueError, SyntaxError):
                pattern = literal
        out.append((text.count("\n", 0, m.start()) + 1, pattern))
    return out


def is_redos_candidate(pattern: str) -> bool:

    return bool(_GROUP_WITH_QUANT.search(pattern)
                or _GROUP_WITH_ALT.search(pattern))


def _probe_char(pattern: str) -> str:
    m = re.search(r"\[([^\]\\]*(?:\\.[^\]\\]*)*)\]", pattern)
    if m:
        for ch in m.group(1):
            if ch not in "\\^]":
                return ch
    for token, char in (("\\d", "1"), ("\\w", "a"), ("\\s", " ")):
        if token in pattern:
            return char
    return "a"


def _validate_redos(pattern: str, timeout: float = 1.5) -> bool | None:

    probe = _probe_char(pattern)

    def run(data: str):
        try:
            r = subprocess.run(
                [sys.executable, "-c", _VALIDATE_SCRIPT, pattern, data],
                capture_output=True, text=True, timeout=timeout)
            return r.returncode == 0
        except subprocess.TimeoutExpired:
            return "timeout"

    if run("a") is not True:
        return None
    tails = ["\n"] if "." in pattern else ["!"]
    for n in (40, 120, 300):
        res = run(probe * n + tails[0])
        if res == "timeout":
            return True
    return False



_ZIP_SINKS = re.compile(
    r"extractall\s*\(|\.extract\s*\(|tarfile\.open|gzip\.open|"
    r"zipfile\.ZipFile|ZipFile\s*\(|unzip\s|gunzip\s")
_SIZE_GUARDS = re.compile(
    r"file_size|max_size|MAX_|\.read\(|decompress\s*\(|"
    r"size\s*[<>=]|info\.file_size|uncompressed_size|limit")

_LOOP_OPEN = re.compile(r"(for|while)\s*\(")
_GROWTH_OP = re.compile(r"\.push\s*\(|\+=|\.concat\s*\(")
_EVAL = re.compile(r"\b(?:eval|exec)\s*\(")
_SHELL_TRUE = re.compile(r"shell\s*=\s*True", re.IGNORECASE)
_SUBPROCESS = re.compile(r"\bsubprocess\.(?:run|Popen|call|check_output|check_call)\s*\(")
_OS_SYSTEM = re.compile(r"\bos\.system\s*\(")
_PICKLE = re.compile(r"\bpickle\.(?:loads?|Unpickler)\s*\(")
_YAML_LOAD = re.compile(r"\byaml\.load\s*\(")


def _mk_finding(plugin: str, title: str, sev: Severity, conf: Confidence,
                cwe: str, remediation: str, path: Path, line, snippet: str) -> Finding:
    loc = f"{path}:{line}" if line else str(path)
    f = Finding(plugin=plugin, category="runtime", title=title, severity=sev,
                confidence=conf, cwe=cwe, remediation=remediation,
                location=loc, target=str(path))
    f.add_evidence("advisory", title, ref=loc, snippet=(snippet or "")[:200])
    return f


def _audit_growth_python(path: Path, source: str) -> list[Finding]:
    findings = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return findings
    for node in ast.walk(tree):
        if not isinstance(node, (ast.For, ast.While)):
            continue
        body = ast.get_source_segment(source, node) or ""
        growth = (".append(" in body or ".extend(" in body
                  or re.search(r"\b\w+\s*\+=", body))
        guarded = any(k in body for k in ("len(", "break", "limit", "max_",
                                          "isinstance", "if "))
        if growth and not guarded:
            snippet = body.strip().splitlines()[0] if body.strip() else ""
            findings.append(_mk_finding(
                "analyze_runtime",
                "Unbounded collection/string growth in loop",
                Severity.LOW, Confidence.WEAK, "CWE-400",
                "Loop appends to a collection or builds a string without an "
                "explicit bound; uncontrolled input can exhaust memory.",
                path, node.lineno, snippet))
    return findings


def _audit_growth_generic(path: Path, text: str) -> list[Finding]:
    findings, reported = [], set()
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        if not _LOOP_OPEN.search(ln) or any(abs(i - j) <= 2 for j in reported):
            continue
        block = "\n".join(lines[i:i + 15])
        if _GROWTH_OP.search(block) and not re.search(r"\bbreak\b|length|limit", block):
            findings.append(_mk_finding(
                "analyze_runtime", "Unbounded collection growth in loop",
                Severity.LOW, Confidence.WEAK, "CWE-400",
                "Loop pushes/appends without an explicit bound.", path,
                i + 1, ln.strip()))
            reported.add(i)
    return findings


def _scan_sinks(text: str) -> list[tuple[int, str, Severity, Confidence, str, str]]:
    out = []
    for m in _EVAL.finditer(text):
        after = text[m.end():m.end() + 80].lstrip()
        if after.startswith(("'", '"')):
            continue
        out.append((text.count("\n", 0, m.start()) + 1,
                    "Dynamic code execution (eval/exec)", Severity.MEDIUM,
                    Confidence.MEDIUM, "CWE-95",
                    "Replace eval/exec with safe parsers/allowlists; never "
                    "evaluate user-controlled strings."))
    for m in _SUBPROCESS.finditer(text):
        if _SHELL_TRUE.search(text[m.start():m.start() + 200]):
            out.append((text.count("\n", 0, m.start()) + 1,
                        "subprocess with shell=True", Severity.MEDIUM,
                        Confidence.MEDIUM, "CWE-78",
                        "Use argument lists (no shell=True) so user input "
                        "cannot reach the shell."))
    for m in _OS_SYSTEM.finditer(text):
        out.append((text.count("\n", 0, m.start()) + 1,
                    "os.system shell execution", Severity.MEDIUM,
                    Confidence.MEDIUM, "CWE-78",
                    "Use subprocess with argument lists or shlex.split; "
                    "os.system passes through the shell."))
    for m in _PICKLE.finditer(text):
        out.append((text.count("\n", 0, m.start()) + 1,
                    "Untrusted pickle deserialization", Severity.MEDIUM,
                    Confidence.MEDIUM, "CWE-502",
                    "Never unpickle untrusted data; use a safe format "
                    "(JSON + schema validation)."))
    for m in _YAML_LOAD.finditer(text):
        after = text[m.end():m.end() + 40]
        if "SafeLoader" in after or "safe_load" in after:
            continue
        out.append((text.count("\n", 0, m.start()) + 1,
                    "yaml.load without SafeLoader", Severity.MEDIUM,
                    Confidence.MEDIUM, "CWE-502",
                    "Use yaml.safe_load; yaml.load can instantiate "
                    "arbitrary Python objects."))
    return out


def audit_codebase(root: str | Path, validate_redos: bool = True,
                   redos_timeout: float = 1.5) -> list[Finding]:
    root = Path(root)
    findings: list[Finding] = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or any(part in EXCLUDE_DIRS for part in p.parts):
            continue
        if p.suffix not in CODE_EXTS:
            continue
        try:
            text = p.read_text(errors="ignore")
        except OSError:
            continue


        for line_no, pattern in _extract_re_patterns(text):
            if not is_redos_candidate(pattern):
                continue
            sev, conf = Severity.MEDIUM, Confidence.MEDIUM
            detail = f"ReDoS-prone regex at {p}:{line_no}"
            if validate_redos:
                result = _validate_redos(pattern, redos_timeout)
                if result is True:
                    sev, conf = Severity.HIGH, Confidence.STRONG
                    detail = (f"ReDoS CONFIRMED: regex '{pattern[:60]}' "
                              f"exceeds timeout on crafted input")
                elif result is None:
                    continue
            findings.append(_mk_finding(
                "analyze_runtime",
                "Catastrophic backtracking (ReDoS)" if conf is Confidence.STRONG
                else "Potential catastrophic backtracking (ReDoS)",
                sev, conf, "CWE-1333",
                "Rewrite the regex to avoid nested quantifiers/alternation "
                "(e.g. atomic groups, possessive quantifiers, or a parser); "
                "enforce input length limits as defense-in-depth.",
                p, line_no, pattern[:120]))


        if _ZIP_SINKS.search(text) and not _SIZE_GUARDS.search(text):
            findings.append(_mk_finding(
                "analyze_runtime", "Archive extraction without size guards",
                Severity.MEDIUM, Confidence.MEDIUM, "CWE-409",
                "Validate uncompressed size before extract; cap member "
                "count and total bytes; use a streaming extractor.",
                p, 0, ""))

        findings += (_audit_growth_python(p, text) if p.suffix == ".py"
                     else _audit_growth_generic(p, text))

        for line_no, title, sev, conf, cwe, rem in _scan_sinks(text):
            findings.append(_mk_finding("analyze_runtime", title, sev, conf,
                                        cwe, rem, p, line_no, ""))
    return findings
