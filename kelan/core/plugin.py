
from __future__ import annotations

import asyncio
import importlib
import inspect
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Optional

import structlog

from kelan.core.finding import Finding, FindingSet

log = structlog.get_logger()


class ScopeKind(str, Enum):
    URL = "url"
    REPO = "repo"
    CODEBASE = "codebase"
    HOST = "host"


@dataclass
class ScanTarget:
    kind: ScopeKind
    value: str
    meta: dict = field(default_factory=dict)

    def display(self) -> str:
        return f"{self.kind.value}:{self.value}"


@dataclass
class ScanConfig:
    values: dict = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)

    def section(self, plugin: str) -> dict:
        return dict(self.values.get(plugin, {}))


@dataclass
class PluginResult:
    plugin: str
    findings: list[Finding] = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    duration_s: float = 0.0
    skipped: bool = False

    def to_dict(self) -> dict:
        return {"plugin": self.plugin,
                "findings": [f.to_dict() for f in self.findings],
                "meta": self.meta, "errors": self.errors,
                "duration_s": round(self.duration_s, 3), "skipped": self.skipped}


class ScanContext:


    def __init__(self, target: ScanTarget, config: ScanConfig,
                 workspace: Path, results: Optional[FindingSet] = None,
                 ollama: Optional[dict] = None):
        self.target = target
        self.config = config
        self.workspace = workspace
        self.results = results or FindingSet()
        self.ollama = ollama or {}
        self._shared: dict = {}

    def publish(self, key: str, value: Any) -> None:
        self._shared[key] = value

    def consume(self, key: str, default: Any = None) -> Any:
        return self._shared.get(key, default)

    def info(self, plugin: str, **kw) -> None:
        log.info(f"plugin_{plugin}", **kw)


class ScanPlugin:


    name: str = ""
    version: str = "0.1"
    description: str = ""
    applies_to: set[ScopeKind] = set()
    requires: tuple[str, ...] = ()

    async def run(self, ctx: ScanContext) -> PluginResult:
        raise NotImplementedError

    def validate(self) -> None:
        if not self.name or not self.applies_to:
            raise ValueError(
                f"{type(self).__name__}: name and applies_to are required")


class PluginRegistry:

    def __init__(self):
        self._plugins: dict[str, ScanPlugin] = {}

    def register(self, plugin: ScanPlugin) -> None:
        plugin.validate()
        if plugin.name in self._plugins:
            raise ValueError(f"duplicate plugin: {plugin.name}")
        self._plugins[plugin.name] = plugin

    def get(self, name: str) -> ScanPlugin:
        return self._plugins[name]

    def names(self) -> list[str]:
        return sorted(self._plugins)

    def applicable(self, kind: ScopeKind) -> list[ScanPlugin]:
        return [p for p in self._plugins.values() if kind in p.applies_to]

    def __len__(self):
        return len(self._plugins)


def _topo_order(plugins: list[ScanPlugin], names: set[str]) -> list[ScanPlugin]:

    by_name = {p.name: p for p in plugins}
    ordered, visited, temp = [], set(), set()

    def visit(name: str):
        if name in visited:
            return
        if name in temp:
            raise ValueError(f"circular plugin dependency at: {name}")
        temp.add(name)
        p = by_name[name]
        for req in p.requires:
            if req in by_name:
                visit(req)
        temp.discard(name)
        visited.add(name)
        ordered.append(p)

    for p in plugins:
        visit(p.name)
    return ordered


def load_plugins_from(module_names: Iterable[str],
                      registry: PluginRegistry) -> int:

    count = 0
    for modname in module_names:
        try:
            mod = importlib.import_module(modname)
        except Exception as exc:
            log.warning("plugin_import_failed", module=modname, error=str(exc))
            continue
        for _, obj in inspect.getmembers(mod, inspect.isclass):
            if (issubclass(obj, ScanPlugin) and obj is not ScanPlugin
                    and obj.name):
                try:
                    registry.register(obj())
                    count += 1
                except Exception as exc:
                    log.warning("plugin_register_failed",
                                module=modname, error=str(exc))
    return count


class Scheduler:


    def __init__(self, registry: PluginRegistry,
                 config: Optional[ScanConfig] = None):
        self.registry = registry
        self.config = config or ScanConfig()
        self.results = FindingSet()
        self._workspace: Optional[Path] = None
        self._made_workspace = False

    def cleanup(self) -> None:
        if self._made_workspace and self._workspace is not None:
            shutil.rmtree(self._workspace, ignore_errors=True)

    async def run(self, target: ScanTarget,
                  only: Optional[set[str]] = None,
                  skip: Optional[set[str]] = None,
                  ) -> tuple[FindingSet, dict[str, PluginResult]]:
        only = only or set()
        skip = skip or set()
        plugins = [p for p in self.registry.applicable(target.kind)
                   if (not only or p.name in only) and p.name not in skip
                   and (getattr(p, "auto", True) or (only and p.name in only))]

        if not plugins:
            log.warning("scheduler_no_plugins", kind=target.kind.value)
            return self.results, {}

        ordered = _topo_order(plugins, {p.name for p in plugins})
        per_plugin: dict[str, PluginResult] = {}

        if self.config.get("workspace"):
            self._workspace = Path(self.config.get("workspace"))
            self._made_workspace = False
        else:
            self._workspace = Path(tempfile.mkdtemp(prefix="kelan-"))
            self._made_workspace = True

        ollama_cfg = self.config.get("ollama") or {}
        use_llm = self.config.get("use_llm", True)
        ollama = ({"endpoint": ollama_cfg.get("endpoint", "http://127.0.0.1:11434"),
                   "model": ollama_cfg.get("model", "qwen2.5-coder:latest")}
                  if use_llm else None)

        ctx = ScanContext(target, self.config, self._workspace,
                          results=self.results, ollama=ollama)

        for plugin in ordered:
            t0 = time.monotonic()
            log.info("scheduler_start", plugin=plugin.name,
                     target=target.display())
            try:
                res = await plugin.run(ctx)
            except Exception as exc:
                log.error("scheduler_plugin_failed", plugin=plugin.name,
                          error=str(exc))
                res = PluginResult(plugin=plugin.name, errors=[str(exc)])
            res.duration_s = time.monotonic() - t0
            per_plugin[plugin.name] = res
            added = self.results.extend(res.findings)
            log.info("scheduler_done", plugin=plugin.name,
                     findings=len(res.findings), new=added,
                     errors=len(res.errors),
                     seconds=round(res.duration_s, 2))
        return self.results, per_plugin
