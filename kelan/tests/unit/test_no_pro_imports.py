from __future__ import annotations

import ast
import os
from pathlib import Path

PRO_MODULE_NAMES = {
    "kelan_pro",
    "enforcement",
    "kelan.enforcement",
    "sentinel",
    "kelan.sentinel",
    "protocol",
    "kelan.protocol",
    "crypto",
    "kelan.crypto",
    "db",
    "kelan.db",
    "trust",
    "kelan.trust",
}


def get_community_python_files() -> list[Path]:
    kelan_root = Path(__file__).resolve().parent.parent.parent
    py_files = []
    for root, dirs, files in os.walk(kelan_root):
        if "tests" in root or "__pycache__" in root:
            continue
        for f in files:
            if f.endswith(".py"):
                py_files.append(Path(root) / f)
    return py_files


def test_community_has_zero_pro_imports():
    """Asserts that no Python source file in the Community edition imports any Pro modules."""
    files = get_community_python_files()
    assert len(files) > 0, "No community Python files found to inspect"

    violations = []

    for path in files:
        with open(path, "r", encoding="utf-8") as f:
            try:
                tree = ast.parse(f.read(), filename=str(path))
            except SyntaxError as e:
                violations.append(f"{path}: Syntax error: {e}")
                continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    for pro in PRO_MODULE_NAMES:
                        if alias.name == pro or alias.name.startswith(f"{pro}."):
                            violations.append(f"{path}:{node.lineno}: Pro import '{alias.name}'")
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                for pro in PRO_MODULE_NAMES:
                    if mod == pro or mod.startswith(f"{pro}.") or (node.level > 0 and mod.startswith(pro)):
                        violations.append(f"{path}:{node.lineno}: Pro import from '{mod}'")

    assert not violations, "Found prohibited Pro imports in Community package:\n" + "\n".join(violations)
