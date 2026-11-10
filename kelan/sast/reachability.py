# ══ Kelan SAST — Reachability & Call Graph Engine ═══════════════════════════════
# License: MIT License (https://opensource.org/licenses/MIT)
# Copyright (c) 2026 Tanush Jain / Kelan Community
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import tree_sitter_javascript as tsjs
import tree_sitter_python as tspython
import tree_sitter_typescript as tsts
from tree_sitter import Language, Parser

from kelan.sast.rules.base import RuleFinding


class ReachabilityVerdict(str, Enum):
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    UNKNOWN = "unknown"


@dataclass
class FunctionNode:
    name: str
    file_path: str
    start_line: int
    end_line: int
    is_entrypoint: bool = False
    entrypoint_type: str = ""  # "http_handler" | "cli_main" | "exported" | "module_scope"
    calls: set[str] = field(default_factory=set)
    has_dynamic_dispatch: bool = False
    is_exported: bool = False


@dataclass
class CallGraph:
    nodes: dict[str, FunctionNode] = field(default_factory=dict)
    entrypoints: set[str] = field(default_factory=set)
    has_global_dynamic_dispatch: bool = False
    is_library_module: bool = False

    def add_edge(self, caller: str, callee: str) -> None:
        if caller in self.nodes:
            self.nodes[caller].calls.add(callee)

    def find_path_from_entrypoints(self, target_func: str) -> list[str] | None:
        """Find the shortest execution path from any entrypoint to target_func using BFS."""
        if target_func in self.entrypoints:
            return [target_func]

        queue: deque[list[str]] = deque([[ep] for ep in self.entrypoints])
        visited: set[str] = set(self.entrypoints)

        while queue:
            path = queue.popleft()
            current = path[-1]

            if current == target_func:
                return path

            curr_node = self.nodes.get(current)
            if not curr_node:
                continue

            for next_call in curr_node.calls:
                if next_call == target_func:
                    return path + [next_call]
                if next_call not in visited and next_call in self.nodes:
                    visited.add(next_call)
                    queue.append(path + [next_call])

        return None


class TreeSitterCallGraphBuilder:
    """Builds an inter-procedural call graph from AST nodes for Python and JS/TS."""

    def __init__(self) -> None:
        self.py_parser = Parser(Language(tspython.language()))
        self.js_parser = Parser(Language(tsjs.language()))
        self.ts_parser = Parser(Language(tsts.language_typescript()))

    def parse(self, file_path: str, code: str | bytes) -> Any:
        code_bytes = code.encode("utf-8") if isinstance(code, str) else code
        ext = Path(file_path).suffix.lower()
        if ext == ".py":
            return self.py_parser.parse(code_bytes)
        elif ext in (".js", ".mjs", ".cjs"):
            return self.js_parser.parse(code_bytes)
        elif ext in (".ts", ".tsx"):
            return self.ts_parser.parse(code_bytes)
        return None

    def build_call_graph(self, file_path: str, code: str, root_node: Any) -> CallGraph:
        cg = CallGraph()
        ext = Path(file_path).suffix.lower()

        if ext == ".py":
            self._build_python_graph(cg, file_path, code, root_node)
        elif ext in (".js", ".ts", ".tsx", ".mjs", ".cjs"):
            self._build_js_graph(cg, file_path, code, root_node)

        return cg

    def _build_python_graph(self, cg: CallGraph, file_path: str, code: str, root: Any) -> None:
        code_bytes = code.encode("utf-8")

        has_main_block = False
        has_http_decorators = False

        # Phase 1: Collect all functions and classify entrypoints
        def collect_funcs(node: Any) -> None:
            nonlocal has_main_block, has_http_decorators

            if node.type == "function_definition":
                name_node = node.child_by_field_name("name")
                name = code_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8") if name_node else "<anon>"
                start_line = node.start_point[0] + 1
                end_line = node.end_point[0] + 1

                func_node = FunctionNode(
                    name=name,
                    file_path=file_path,
                    start_line=start_line,
                    end_line=end_line,
                )

                # Check decorators for HTTP route handlers or CLI entrypoints
                parent = node.parent
                decorators = []
                if parent and parent.type == "decorated_definition":
                    for child in parent.children:
                        if child.type == "decorator":
                            dec_text = code_bytes[child.start_byte:child.end_byte].decode("utf-8").lower()
                            decorators.append(dec_text)

                for dec in decorators:
                    if any(kw in dec for kw in ("route", "get", "post", "put", "delete", "patch", "api_route", "endpoint")):
                        func_node.is_entrypoint = True
                        func_node.entrypoint_type = "http_handler"
                        has_http_decorators = True
                    elif any(kw in dec for kw in ("click.command", "app.command", "cli.command", "task")):
                        func_node.is_entrypoint = True
                        func_node.entrypoint_type = "cli_main"

                # Check conventional entrypoint function names
                if name in ("main", "cli", "run", "handler", "lambda_handler"):
                    func_node.is_entrypoint = True
                    func_node.entrypoint_type = "cli_main"

                cg.nodes[name] = func_node

            elif node.type == "if_statement":
                # Check for `if __name__ == '__main__':`
                cond = node.child_by_field_name("condition")
                if cond:
                    cond_text = code_bytes[cond.start_byte:cond.end_byte].decode("utf-8")
                    if "__name__" in cond_text and "__main__" in cond_text:
                        has_main_block = True

            for child in node.children:
                collect_funcs(child)

        collect_funcs(root)

        # Module scope node
        module_node = FunctionNode(
            name="<module>",
            file_path=file_path,
            start_line=1,
            end_line=len(code.splitlines()) or 1,
            is_entrypoint=True,
            entrypoint_type="module_scope",
        )
        cg.nodes["<module>"] = module_node
        cg.entrypoints.add("<module>")

        for name, fn in cg.nodes.items():
            if fn.is_entrypoint:
                cg.entrypoints.add(name)

        # Determine if this file is a standalone executable or a library module
        cg.is_library_module = not (has_main_block or has_http_decorators)

        # Phase 2: Traverse function bodies to identify call edges and dynamic dispatch
        def inspect_calls(node: Any, current_func: str) -> None:
            if node.type == "call":
                func_child = node.child_by_field_name("function")
                if func_child:
                    callee_text = code_bytes[func_child.start_byte:func_child.end_byte].decode("utf-8")
                    
                    # Direct function call
                    if func_child.type == "identifier":
                        cg.add_edge(current_func, callee_text)
                    elif func_child.type == "attribute":
                        attr_child = func_child.child_by_field_name("attribute")
                        if attr_child:
                            attr_name = code_bytes[attr_child.start_byte:attr_child.end_byte].decode("utf-8")
                            cg.add_edge(current_func, attr_name)

                    # Dynamic dispatch check
                    if callee_text in ("getattr", "setattr", "eval", "exec", "__import__", "locals", "globals"):
                        cg.nodes[current_func].has_dynamic_dispatch = True
                        cg.has_global_dynamic_dispatch = True

            # If inside `if __name__ == '__main__':`, link calls from main block
            if node.type == "if_statement":
                cond = node.child_by_field_name("condition")
                if cond:
                    cond_text = code_bytes[cond.start_byte:cond.end_byte].decode("utf-8")
                    if "__name__" in cond_text and "__main__" in cond_text:
                        self._extract_calls_in_block(node, cg, "<module>", code_bytes)

            for child in node.children:
                if child.type == "function_definition":
                    name_node = child.child_by_field_name("name")
                    fn_name = code_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8") if name_node else "<anon>"
                    for body_child in child.children:
                        inspect_calls(body_child, fn_name)
                else:
                    inspect_calls(child, current_func)

        for child in root.children:
            if child.type != "function_definition":
                inspect_calls(child, "<module>")
            else:
                name_node = child.child_by_field_name("name")
                fn_name = code_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8") if name_node else "<anon>"
                inspect_calls(child, fn_name)

    def _build_js_graph(self, cg: CallGraph, file_path: str, code: str, root: Any) -> None:
        code_bytes = code.encode("utf-8")

        # Phase 1: Collect JS/TS functions & exports
        def collect_funcs(node: Any) -> None:
            name: str | None = None
            is_exported = False

            if node.type == "export_statement":
                is_exported = True

            if node.type == "function_declaration":
                name_node = node.child_by_field_name("name")
                if name_node:
                    name = code_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8")
            elif node.type == "variable_declarator":
                # const foo = () => ... or const foo = function() ...
                val = node.child_by_field_name("value")
                if val and val.type in ("arrow_function", "function_expression"):
                    name_node = node.child_by_field_name("name")
                    if name_node:
                        name = code_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8")

            if name:
                start_line = node.start_point[0] + 1
                end_line = node.end_point[0] + 1
                func_node = FunctionNode(
                    name=name,
                    file_path=file_path,
                    start_line=start_line,
                    end_line=end_line,
                    is_exported=is_exported,
                )
                if is_exported or name in ("handler", "main", "start", "run"):
                    func_node.is_entrypoint = True
                    func_node.entrypoint_type = "exported" if is_exported else "cli_main"

                cg.nodes[name] = func_node

            for child in node.children:
                collect_funcs(child)

        collect_funcs(root)

        # Module scope
        module_node = FunctionNode(
            name="<top-level>",
            file_path=file_path,
            start_line=1,
            end_line=len(code.splitlines()) or 1,
            is_entrypoint=True,
            entrypoint_type="module_scope",
        )
        cg.nodes["<top-level>"] = module_node
        cg.entrypoints.add("<top-level>")

        for name, fn in cg.nodes.items():
            if fn.is_entrypoint:
                cg.entrypoints.add(name)

        # Phase 2: Traverse JS calls & route handlers
        def inspect_calls(node: Any, current_func: str) -> None:
            if node.type == "call_expression":
                fn_child = node.child_by_field_name("function")
                if fn_child:
                    callee_text = code_bytes[fn_child.start_byte:fn_child.end_byte].decode("utf-8")

                    # Check Express / Fastify / Koa HTTP route registration: app.get('/', handler)
                    if fn_child.type == "member_expression":
                        prop = fn_child.child_by_field_name("property")
                        if prop:
                            prop_name = code_bytes[prop.start_byte:prop.end_byte].decode("utf-8").lower()
                            if prop_name in ("get", "post", "put", "delete", "patch", "use", "all"):
                                # Route callback might be an argument
                                args_node = node.child_by_field_name("arguments")
                                if args_node:
                                    for arg in args_node.children:
                                        if arg.type == "identifier":
                                            handler_name = code_bytes[arg.start_byte:arg.end_byte].decode("utf-8")
                                            if handler_name in cg.nodes:
                                                cg.nodes[handler_name].is_entrypoint = True
                                                cg.nodes[handler_name].entrypoint_type = "http_handler"
                                                cg.entrypoints.add(handler_name)

                            cg.add_edge(current_func, prop_name)

                    if fn_child.type == "identifier":
                        cg.add_edge(current_func, callee_text)

                    # Dynamic dispatch in JS
                    if callee_text in ("eval", "Function", "Reflect.apply"):
                        cg.nodes[current_func].has_dynamic_dispatch = True
                        cg.has_global_dynamic_dispatch = True

            for child in node.children:
                if child.type == "function_declaration" or child.type == "variable_declarator" and child.child_by_field_name("value") and child.child_by_field_name("value").type in ("arrow_function", "function_expression"):
                    name_node = child.child_by_field_name("name")
                    fn_name = code_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8") if name_node else "<anon>"
                    inspect_calls(child, fn_name)
                else:
                    inspect_calls(child, current_func)

        for child in root.children:
            inspect_calls(child, "<top-level>")

    def _extract_calls_in_block(self, node: Any, cg: CallGraph, caller: str, code_bytes: bytes) -> None:
        if node.type == "call":
            func_child = node.child_by_field_name("function")
            if func_child and func_child.type == "identifier":
                callee_name = code_bytes[func_child.start_byte:func_child.end_byte].decode("utf-8")
                cg.add_edge(caller, callee_name)
        for child in node.children:
            self._extract_calls_in_block(child, cg, caller, code_bytes)


class ReachabilityEvaluator:
    """Evaluates whether findings or vulnerable dependency symbols are reachable from entrypoints."""

    def __init__(self) -> None:
        self.builder = TreeSitterCallGraphBuilder()

    def evaluate_findings(
        self,
        file_path: str,
        code: str,
        root_node: Any,
        findings: list[RuleFinding],
    ) -> list[RuleFinding]:
        """Annotates each finding with reachability_verdict and reachability_path."""
        if not findings:
            return findings

        cg = self.builder.build_call_graph(file_path, code, root_node)

        for finding in findings:
            # 1. Determine enclosing function for the finding
            enclosing = self._find_enclosing_function(cg, finding.line)
            finding.enclosing_function = enclosing

            # 2. Check top-level execution
            if enclosing in ("<module>", "<top-level>"):
                finding.reachability_verdict = ReachabilityVerdict.REACHABLE.value
                finding.reachability_path = [enclosing]
                continue

            # 3. Check if enclosing function is already an entrypoint
            if enclosing in cg.entrypoints:
                finding.reachability_verdict = ReachabilityVerdict.REACHABLE.value
                finding.reachability_path = [enclosing]
                continue

            # 4. Search for static path from any entrypoint
            path = cg.find_path_from_entrypoints(enclosing)
            if path is not None:
                finding.reachability_verdict = ReachabilityVerdict.REACHABLE.value
                finding.reachability_path = path
                continue

            # 5. If no static path exists, evaluate whether it's UNREACHABLE or UNKNOWN.
            # CRITICAL RULE: "Unknown stays unknown; never round it up or down."
            # Limits to static resolution:
            # - Dynamic dispatch present (getattr, eval, function dicts, reflections)
            # - Library modules where public functions may be called by external consumers
            # - Enclosing function is passed as a callback or identifier
            is_dynamic = (
                cg.has_global_dynamic_dispatch
                or (enclosing in cg.nodes and cg.nodes[enclosing].has_dynamic_dispatch)
                or cg.is_library_module
                or (enclosing in cg.nodes and cg.nodes[enclosing].is_exported)
            )

            if is_dynamic:
                finding.reachability_verdict = ReachabilityVerdict.UNKNOWN.value
                finding.reachability_path = []
            else:
                # In a self-contained application entry file where all entrypoints are known
                # and no dynamic dispatch occurs, if no path exists, the code is unreachable.
                finding.reachability_verdict = ReachabilityVerdict.UNREACHABLE.value
                finding.reachability_path = []

        return findings

    def _find_enclosing_function(self, cg: CallGraph, line: int) -> str:
        best_name = "<module>" if "<module>" in cg.nodes else "<top-level>"
        smallest_span = float("inf")

        for name, fn in cg.nodes.items():
            if name in ("<module>", "<top-level>"):
                continue
            if fn.start_line <= line <= fn.end_line:
                span = fn.end_line - fn.start_line
                if span < smallest_span:
                    smallest_span = span
                    best_name = name

        return best_name
