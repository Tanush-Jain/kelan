# ══ Kelan SAST — JavaScript / TypeScript AST Deterministic Rules ══════════════
# License: MIT License (https://opensource.org/licenses/MIT)
# Copyright (c) 2026 Tanush Jain / Kelan Community

from __future__ import annotations

import re
from typing import Any

from kelan.sast.rules.base import RuleConfidence, RuleFinding, RuleSeverity, SastRule
from kelan.sast.rules.python_rules import GenericHardcodedSecretsRule, _find_nodes_of_type, _node_text


def _get_enclosing_js_function(node: Any, code: str) -> str:
    cur = node
    while cur is not None:
        if cur.type in ("function_declaration", "method_definition", "function"):
            name_node = cur.child_by_field_name("name")
            if name_node:
                return _node_text(name_node, code)
        elif cur.type == "variable_declarator":
            name_node = cur.child_by_field_name("name")
            val_node = cur.child_by_field_name("value")
            if val_node and val_node.type in ("arrow_function", "function"):
                return _node_text(name_node, code)
        cur = cur.parent
    return ""


class JSSQLInjectionRule(SastRule):
    rule_id = "KELAN-JS-SQLI-01"
    cwe = "CWE-89"
    title = "SQL Injection: Unparameterized Database Query"
    severity = RuleSeverity.CRITICAL
    confidence = RuleConfidence.HIGH
    remediation = "Use parameterized queries with placeholder syntax (e.g. db.query('SELECT * FROM users WHERE id = $1', [id]))."
    languages = ("javascript", "typescript")

    QUERY_NAMES = {"query", "raw", "execute", "exec"}

    def scan_file(self, file_path: str, code: str, root_node: Any) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        calls = _find_nodes_of_type(root_node, {"call_expression"})

        for call in calls:
            fn_node = call.child_by_field_name("function")
            args_node = call.child_by_field_name("arguments")
            if not fn_node or not args_node:
                continue

            fn_text = _node_text(fn_node, code)
            is_query = any(fn_text.endswith("." + q) or fn_text == q for q in self.QUERY_NAMES)
            if not is_query:
                continue

            args = [c for c in args_node.children if c.type not in ("(", ")", ",")]
            if not args:
                continue

            first_arg = args[0]
            first_text = _node_text(first_arg, code)

            # Check if template literal has substitutions or binary operator with string +
            is_sqli = False
            has_sql_verb = bool(re.search(r'''(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|FROM|WHERE)\b''', first_text))

            if first_arg.type == "template_string":
                has_subs = any(c.type == "template_substitution" for c in first_arg.children)
                if has_subs and has_sql_verb:
                    is_sqli = True
            elif first_arg.type == "binary_expression" and "+" in first_text and has_sql_verb:
                is_sqli = True

            if is_sqli:
                encl_fn = _get_enclosing_js_function(call, code)
                findings.append(RuleFinding(
                    rule_id=self.rule_id,
                    cwe=self.cwe,
                    title=self.title,
                    description=f"Potential SQL injection detected via dynamic query construction in '{fn_text}' in {file_path}.",
                    severity=self.severity,
                    confidence=self.confidence,
                    file_path=file_path,
                    line=call.start_point[0] + 1,
                    end_line=call.end_point[0] + 1,
                    snippet=_node_text(call, code),
                    sink=fn_text,
                    source_to_sink_evidence=f"Dynamic SQL query expression: {first_text[:120]}",
                    remediation=self.remediation,
                    enclosing_function=encl_fn,
                ))

        return findings


class JSXSSSinkRule(SastRule):
    rule_id = "KELAN-JS-XSS-01"
    cwe = "CWE-79"
    title = "Cross-Site Scripting: Dangerous DOM Sink Assignment"
    severity = RuleSeverity.HIGH
    confidence = RuleConfidence.HIGH
    remediation = "Use textContent or a sanitized DOM library (e.g. DOMPurify.sanitize) before injecting raw HTML."
    languages = ("javascript", "typescript")

    def scan_file(self, file_path: str, code: str, root_node: Any) -> list[RuleFinding]:
        findings: list[RuleFinding] = []

        # 1. Check assignments: element.innerHTML = user_val, element.outerHTML = ...
        assignments = _find_nodes_of_type(root_node, {"assignment_expression"})
        for asgn in assignments:
            left = asgn.child_by_field_name("left")
            right = asgn.child_by_field_name("right")
            if not left or not right:
                continue

            left_text = _node_text(left, code)
            if left_text.endswith(".innerHTML") or left_text.endswith(".outerHTML"):
                encl_fn = _get_enclosing_js_function(asgn, code)
                findings.append(RuleFinding(
                    rule_id=self.rule_id,
                    cwe=self.cwe,
                    title=self.title,
                    description=f"Direct assignment to unescaped HTML DOM sink '{left_text}' allows client-side script execution.",
                    severity=self.severity,
                    confidence=self.confidence,
                    file_path=file_path,
                    line=asgn.start_point[0] + 1,
                    end_line=asgn.end_point[0] + 1,
                    snippet=_node_text(asgn, code),
                    sink=left_text,
                    source_to_sink_evidence=f"Assignment to {left_text}: {_node_text(right, code)[:80]}",
                    remediation=self.remediation,
                    enclosing_function=encl_fn,
                ))

        # 2. Check document.write(...) calls
        calls = _find_nodes_of_type(root_node, {"call_expression"})
        for call in calls:
            fn_node = call.child_by_field_name("function")
            if not fn_node:
                continue
            fn_text = _node_text(fn_node, code)
            if fn_text in ("document.write", "document.writeln"):
                encl_fn = _get_enclosing_js_function(call, code)
                findings.append(RuleFinding(
                    rule_id=self.rule_id,
                    cwe=self.cwe,
                    title="Cross-Site Scripting: document.write Sink",
                    description=f"Use of '{fn_text}' executes raw markup and script payloads in client browsers.",
                    severity=self.severity,
                    confidence=self.confidence,
                    file_path=file_path,
                    line=call.start_point[0] + 1,
                    end_line=call.end_point[0] + 1,
                    snippet=_node_text(call, code),
                    sink=fn_text,
                    source_to_sink_evidence=f"Call to {fn_text}",
                    remediation=self.remediation,
                    enclosing_function=encl_fn,
                ))

        # 3. Check React dangerouslySetInnerHTML
        pairs = _find_nodes_of_type(root_node, {"pair", "jsx_attribute"})
        for p in pairs:
            p_text = _node_text(p, code)
            if "dangerouslySetInnerHTML" in p_text:
                encl_fn = _get_enclosing_js_function(p, code)
                findings.append(RuleFinding(
                    rule_id=self.rule_id,
                    cwe=self.cwe,
                    title="Cross-Site Scripting: React dangerouslySetInnerHTML Sink",
                    description="dangerouslySetInnerHTML bypasses React's automatic string escaping.",
                    severity=self.severity,
                    confidence=self.confidence,
                    file_path=file_path,
                    line=p.start_point[0] + 1,
                    end_line=p.end_point[0] + 1,
                    snippet=p_text[:120],
                    sink="dangerouslySetInnerHTML",
                    source_to_sink_evidence="Usage of dangerouslySetInnerHTML",
                    remediation=self.remediation,
                    enclosing_function=encl_fn,
                ))

        return findings


class JSCommandInjectionRule(SastRule):
    rule_id = "KELAN-JS-CMDI-01"
    cwe = "CWE-78"
    title = "Command Injection: child_process Execution Sink"
    severity = RuleSeverity.HIGH
    confidence = RuleConfidence.HIGH
    remediation = "Use child_process.execFile or spawn with argument arrays without shell options."
    languages = ("javascript", "typescript")

    def scan_file(self, file_path: str, code: str, root_node: Any) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        calls = _find_nodes_of_type(root_node, {"call_expression"})

        for call in calls:
            fn_node = call.child_by_field_name("function")
            args_node = call.child_by_field_name("arguments")
            if not fn_node or not args_node:
                continue

            fn_text = _node_text(fn_node, code)
            is_exec = (
                fn_text in ("exec", "child_process.exec", "execSync", "child_process.execSync")
                or fn_text.endswith(".exec")
                or fn_text.endswith(".execSync")
            )
            is_spawn_shell = (
                (fn_text in ("spawn", "child_process.spawn", "spawnSync") or fn_text.endswith(".spawn"))
                and "shell: true" in _node_text(args_node, code)
            )

            if is_exec or is_spawn_shell:
                encl_fn = _get_enclosing_js_function(call, code)
                findings.append(RuleFinding(
                    rule_id=self.rule_id,
                    cwe=self.cwe,
                    title=self.title,
                    description=f"Command execution sink '{fn_text}' executes commands in system shell.",
                    severity=self.severity,
                    confidence=self.confidence,
                    file_path=file_path,
                    line=call.start_point[0] + 1,
                    end_line=call.end_point[0] + 1,
                    snippet=_node_text(call, code),
                    sink=fn_text,
                    source_to_sink_evidence=f"Call to {fn_text} with command arguments: {_node_text(args_node, code)[:100]}",
                    remediation=self.remediation,
                    enclosing_function=encl_fn,
                ))

        return findings


class JSPathTraversalRule(SastRule):
    rule_id = "KELAN-JS-PATH-01"
    cwe = "CWE-22"
    title = "Path Traversal: Unvalidated File System Access"
    severity = RuleSeverity.HIGH
    confidence = RuleConfidence.MEDIUM
    remediation = "Validate paths with path.resolve and path.relative against a safe root directory."
    languages = ("javascript", "typescript")

    FS_CALLS = {"fs.readFile", "fs.readFileSync", "fs.createReadStream", "res.sendFile", "fs.unlink"}

    def scan_file(self, file_path: str, code: str, root_node: Any) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        calls = _find_nodes_of_type(root_node, {"call_expression"})

        # Track variables assigned from path.join / template strings
        declarators = _find_nodes_of_type(root_node, {"variable_declarator"})
        var_to_dynamic_path: dict[str, Any] = {}
        for decl in declarators:
            name_node = decl.child_by_field_name("name")
            val_node = decl.child_by_field_name("value")
            if name_node and val_node:
                name_txt = _node_text(name_node, code).strip()
                val_txt = _node_text(val_node, code)
                if val_node.type == "call_expression":
                    fn_child = val_node.child_by_field_name("function")
                    if fn_child and _node_text(fn_child, code) in ("path.join", "path.resolve"):
                        var_to_dynamic_path[name_txt] = (decl, val_txt)
                elif val_node.type == "template_string" and any(c.type == "template_substitution" for c in val_node.children):
                    if re.search(r'''(?:path|file|name|dir|doc|target)''', val_txt, re.IGNORECASE):
                        var_to_dynamic_path[name_txt] = (decl, val_txt)

        for call in calls:
            fn_node = call.child_by_field_name("function")
            args_node = call.child_by_field_name("arguments")
            if not fn_node or not args_node:
                continue

            fn_text = _node_text(fn_node, code)
            if any(fn_text == cl or fn_text.endswith("." + cl.split(".")[-1]) for cl in self.FS_CALLS):
                args = [c for c in args_node.children if c.type not in ("(", ")", ",")]
                if not args:
                    continue
                arg_0 = args[0]
                arg_text = _node_text(arg_0, code)
                is_traversal = False
                source_evidence = ""

                # Case A: Direct dynamic template literal or binary expression
                if (arg_0.type == "template_string" and any(c.type == "template_substitution" for c in arg_0.children)) or (
                    arg_0.type == "binary_expression" and "+" in arg_text
                ):
                    is_traversal = True
                    source_evidence = f"Directly concatenated path '{arg_text[:60]}'"
                # Case B: Tainted variable assigned from path.join
                elif arg_text in var_to_dynamic_path:
                    decl_node, decl_val = var_to_dynamic_path[arg_text]
                    is_traversal = True
                    source_evidence = f"Variable '{arg_text}' assigned dynamic path at line {decl_node.start_point[0] + 1}: {decl_val}"

                if is_traversal:
                    encl_fn = _get_enclosing_js_function(call, code)
                    findings.append(RuleFinding(
                        rule_id=self.rule_id,
                        cwe=self.cwe,
                        title=self.title,
                        description=f"File access with dynamically constructed path '{arg_text[:60]}' in '{fn_text}'.",
                        severity=self.severity,
                        confidence=self.confidence,
                        file_path=file_path,
                        line=call.start_point[0] + 1,
                        end_line=call.end_point[0] + 1,
                        snippet=_node_text(call, code),
                        sink=fn_text,
                        source_to_sink_evidence=source_evidence,
                        remediation=self.remediation,
                        enclosing_function=encl_fn,
                    ))

        return findings


class JSDangerousEvalRule(SastRule):
    rule_id = "KELAN-JS-EVAL-01"
    cwe = "CWE-95"
    title = "Dangerous Dynamic Code Execution (eval/Function)"
    severity = RuleSeverity.HIGH
    confidence = RuleConfidence.HIGH
    remediation = "Avoid eval() and Function constructor; parse structured data with JSON.parse()."
    languages = ("javascript", "typescript")

    def scan_file(self, file_path: str, code: str, root_node: Any) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        calls = _find_nodes_of_type(root_node, {"call_expression", "new_expression"})

        for call in calls:
            fn_node = call.child_by_field_name("function") or call.child_by_field_name("constructor")
            if not fn_node:
                continue
            fn_text = _node_text(fn_node, code)

            if fn_text in ("eval", "Function"):
                encl_fn = _get_enclosing_js_function(call, code)
                findings.append(RuleFinding(
                    rule_id=self.rule_id,
                    cwe=self.cwe,
                    title=self.title,
                    description=f"Direct invocation of '{fn_text}' executes arbitrary JavaScript in the runtime scope.",
                    severity=self.severity,
                    confidence=self.confidence,
                    file_path=file_path,
                    line=call.start_point[0] + 1,
                    end_line=call.end_point[0] + 1,
                    snippet=_node_text(call, code),
                    sink=fn_text,
                    source_to_sink_evidence=f"Call to dynamic execution sink: {fn_text}",
                    remediation=self.remediation,
                    enclosing_function=encl_fn,
                ))

        return findings


class JSSSRFRule(SastRule):
    rule_id = "KELAN-JS-SSRF-01"
    cwe = "CWE-918"
    title = "Server-Side Request Forgery: Dynamic Network Request"
    severity = RuleSeverity.HIGH
    confidence = RuleConfidence.MEDIUM
    remediation = "Validate request targets against an allowed domain list and disallow private IP ranges."
    languages = ("javascript", "typescript")

    def scan_file(self, file_path: str, code: str, root_node: Any) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        calls = _find_nodes_of_type(root_node, {"call_expression"})

        for call in calls:
            fn_node = call.child_by_field_name("function")
            args_node = call.child_by_field_name("arguments")
            if not fn_node or not args_node:
                continue

            fn_text = _node_text(fn_node, code)
            is_client = fn_text in ("fetch", "axios.get", "axios.post", "http.get", "https.get", "request")
            if not is_client:
                continue

            args = [c for c in args_node.children if c.type not in ("(", ")", ",")]
            if not args:
                continue
            arg_0 = args[0]
            if arg_0.type in ("identifier", "binary_expression") or (
                arg_0.type == "template_string" and any(c.type == "template_substitution" for c in arg_0.children)
            ):
                encl_fn = _get_enclosing_js_function(call, code)
                findings.append(RuleFinding(
                    rule_id=self.rule_id,
                    cwe=self.cwe,
                    title=self.title,
                    description=f"Outbound network request with dynamic target in '{fn_text}'.",
                    severity=self.severity,
                    confidence=self.confidence,
                    file_path=file_path,
                    line=call.start_point[0] + 1,
                    end_line=call.end_point[0] + 1,
                    snippet=_node_text(call, code),
                    sink=fn_text,
                    source_to_sink_evidence=f"Target URL: {_node_text(arg_0, code)}",
                    remediation=self.remediation,
                    enclosing_function=encl_fn,
                ))

        return findings


class JSWeakCryptoRule(SastRule):
    rule_id = "KELAN-JS-CRYPTO-01"
    cwe = "CWE-327"
    title = "Weak Cryptography: MD5/SHA1 Hash Function"
    severity = RuleSeverity.MEDIUM
    confidence = RuleConfidence.HIGH
    remediation = "Use SHA-256 (crypto.createHash('sha256')) or modern key derivation functions."
    languages = ("javascript", "typescript")

    def scan_file(self, file_path: str, code: str, root_node: Any) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        calls = _find_nodes_of_type(root_node, {"call_expression"})

        for call in calls:
            fn_node = call.child_by_field_name("function")
            args_node = call.child_by_field_name("arguments")
            if not fn_node or not args_node:
                continue

            fn_text = _node_text(fn_node, code)
            if fn_text.endswith(".createHash") or fn_text == "createHash":
                args_text = _node_text(args_node, code).lower()
                if "'md5'" in args_text or '"md5"' in args_text or "'sha1'" in args_text or '"sha1"' in args_text:
                    encl_fn = _get_enclosing_js_function(call, code)
                    findings.append(RuleFinding(
                        rule_id=self.rule_id,
                        cwe=self.cwe,
                        title=self.title,
                        description=f"Cryptographic hash created with broken algorithm in '{fn_text}{args_text}'.",
                        severity=self.severity,
                        confidence=self.confidence,
                        file_path=file_path,
                        line=call.start_point[0] + 1,
                        end_line=call.end_point[0] + 1,
                        snippet=_node_text(call, code),
                        sink=fn_text,
                        source_to_sink_evidence=f"Call to createHash with {args_text}",
                        remediation=self.remediation,
                        enclosing_function=encl_fn,
                    ))

        return findings


JAVASCRIPT_RULES: list[SastRule] = [
    JSSQLInjectionRule(),
    JSXSSSinkRule(),
    JSCommandInjectionRule(),
    JSPathTraversalRule(),
    JSDangerousEvalRule(),
    JSSSRFRule(),
    JSWeakCryptoRule(),
    GenericHardcodedSecretsRule(),
]
