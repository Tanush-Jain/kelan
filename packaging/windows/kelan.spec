# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path
import os
import sys

block_cipher = None

# Root directory is two levels up from packaging/windows
root_dir = Path(__file__).resolve().parent.parent.parent

datas = [
    (str(root_dir / "static"), "static"),
]
dash_dist = root_dir / "kelan-dashboard" / "dist"
if dash_dist.exists():
    datas.append((str(dash_dist), "kelan-dashboard/dist"))
elif (root_dir / "kelan-dashboard").exists():
    datas.append((str(root_dir / "kelan-dashboard"), "kelan-dashboard"))

hiddenimports = [
    "tree_sitter",
    "tree_sitter_python",
    "tree_sitter_javascript",
    "tree_sitter_typescript",
    "cryptography",
    "cryptography.hazmat.primitives.asymmetric.ed25519",
    "sqlite3",
    "tomllib",
    "uvicorn",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.websockets.auto",
    "fastapi",
    "httpx",
    "structlog",
    "rich",
    "rich.panel",
    "rich.table",
    "rich.progress",
    "rich.prompt",
    "kelan",
    "kelan.cli",
    "kelan.cli.main",
    "kelan.setup",
    "kelan.doctor",
    "kelan.run",
    "kelan.core",
    "kelan.core.finding",
    "kelan.core.plugin",
    "kelan.plugins",
    "kelan.plugins.sca",
    "kelan.plugins.ports",
    "kelan.plugins.sast_adapter",
    "kelan.plugins.dast_adapter",
    "kelan.plugins.analyze_ratelimit",
    "kelan.plugins.runtime",
    "kelan.plugins.cloud",
    "kelan.plugins.chains",
    "kelan.intel",
    "kelan.intel.db",
    "kelan.intel.models",
    "kelan.intel.updater",
    "kelan.intel.bundle",
    "kelan.intel.trending",
    "kelan.intel.cli",
    "kelan.intel.version_match",
    "kelan.intel.fetchers",
    "kelan.intel.fetchers.base",
    "kelan.intel.fetchers.cisa",
    "kelan.intel.fetchers.epss",
    "kelan.intel.fetchers.ghsa",
    "kelan.intel.fetchers.nvd",
    "kelan.intel.fetchers.osv",
]

try:
    from PyInstaller.utils.hooks import collect_all
    for ts_mod in ("tree_sitter_python", "tree_sitter_javascript", "tree_sitter_typescript"):
        try:
            d, b, h = collect_all(ts_mod)
            datas.extend(d)
            hiddenimports.extend(h)
        except Exception:
            pass
except Exception:
    pass

a = Analysis(
    [str(root_dir / "kelan" / "cli" / "main.py")],
    pathex=[str(root_dir)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "matplotlib",
        "scipy",
        "numpy",
        "IPython",
        "kelan_pro",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="kelan",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="kelan",
)

