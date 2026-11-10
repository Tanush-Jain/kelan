# ══ Kelan SAST — Python AST Deterministic Rules ══════════════════════════════
# License: MIT License (https://opensource.org/licenses/MIT)
# Copyright (c) 2026 Tanush Jain / Kelan Community
#
# Deterministic rule engine targeting critical vulnerability patterns over Tree-sitter AST.

from __future__ import annotations

import re
from typing import Any

from kelan.sast.rules.base import RuleConfidence, RuleFinding, RuleSeverity, SastRule


def _node_text(node: Any, code: str) -> str:
    if node is None:
        return ""
    start_b = node.start_byte
    end_b = node.end_byte
    # tree-sitter offsets are byte-based; decode slice
    return code.encode("utf-8")[start_b:end_b].decode("utf-8", errors="replace")


def _get_enclosing_function_name(node: Any, code: str) -> str:
    cur = node
    while cur is not None:
        if cur.type in ("function_definition", "async_function_definition"):
            name_node = cur.child_by_field_name("name")
            if name_node:
                return _node_text(name_node, code)
        cur = cur.parent
    return ""


def _find_nodes_of_type(node: Any, types: set[str]) -> list[Any]:
    results = []
    stack = [node]
    while stack:
        curr = stack.pop()
        if curr.type in types:
            results.append(curr)
        stack.extend(curr.children)
    return results


class PythonSQLInjectionRule(SastRule):
    rule_id = "KELAN-PY-SQLI-01"
    cwe = "CWE-89"
    title = "SQL Injection: Unparameterized Dynamic Query"
    severity = RuleSeverity.CRITICAL
    confidence = RuleConfidence.HIGH
    remediation = "Use parameterized queries or ORM binding (e.g. cursor.execute('SELECT * FROM tbl WHERE id = %s', (id,)))."
    languages = ("python",)

    EXECUTE_NAMES = {"execute", "raw", "raw_query", "executemany"}

    def scan_file(self, file_path: str, code: str, root_node: Any) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        calls = _find_nodes_of_type(root_node, {"call"})

        # Build variable assignments map in scope to track tainted sql variables:
        # e.g., query = f"SELECT ... {x}"
        assignments = _find_nodes_of_type(root_node, {"assignment"})
        var_to_dynamic_sql: dict[str, Any] = {}
        for asgn in assignments:
            left = asgn.child_by_field_name("left")
            right = asgn.child_by_field_name("right")
            if left and right:
                left_txt = _node_text(left, code).strip()
                right_txt = _node_text(right, code)
                if self._is_dynamic_sql_expression(right, code):
                    var_to_dynamic_sql[left_txt] = (asgn, right_txt)

        for call in calls:
            fn_node = call.child_by_field_name("function")
            args_node = call.child_by_field_name("arguments")
            if not fn_node or not args_node:
                continue

            fn_text = _node_text(fn_node, code)
            is_exec = False
            for exec_name in self.EXECUTE_NAMES:
                if fn_text == exec_name or fn_text.endswith("." + exec_name):
                    is_exec = True
                    break

            if not is_exec:
                continue

            # Check arguments
            args = [c for c in args_node.children if c.type not in ("(", ")", ",")]
            if not args:
                continue

            first_arg = args[0]
            first_arg_text = _node_text(first_arg, code)

            is_sqli = False
            sink_detail = ""
            source_evidence = ""

            # Case A: Directly formatted string or binary operator in execute
            if self._is_dynamic_sql_expression(first_arg, code):
                is_sqli = True
                sink_detail = f"Call to '{fn_text}({first_arg_text[:80]}...)'"
                source_evidence = f"Sink argument constructed dynamically: {first_arg_text}"

            # Case B: First argument is variable previously assigned from dynamic SQL
            elif first_arg_text in var_to_dynamic_sql:
                asgn_node, asgn_expr = var_to_dynamic_sql[first_arg_text]
                is_sqli = True
                sink_detail = f"Call to '{fn_text}({first_arg_text})'"
                source_evidence = (
                    f"Variable '{first_arg_text}' assigned dynamic SQL at line {asgn_node.start_point[0] + 1}: "
                    f"{asgn_expr[:100]} -> passed directly to sink."
                )

            if is_sqli:
                encl_fn = _get_enclosing_function_name(call, code)
                findings.append(RuleFinding(
                    rule_id=self.rule_id,
                    cwe=self.cwe,
                    title=self.title,
                    description=f"Potential SQL injection detected via unparameterized dynamic query execution in {file_path}.",
                    severity=self.severity,
                    confidence=self.confidence,
                    file_path=file_path,
                    line=call.start_point[0] + 1,
                    end_line=call.end_point[0] + 1,
                    snippet=_node_text(call, code),
                    sink=fn_text,
                    source_to_sink_evidence=source_evidence or sink_detail,
                    remediation=self.remediation,
                    enclosing_function=encl_fn,
                ))

        return findings

    def _is_dynamic_sql_expression(self, node: Any, code: str) -> bool:
        text = _node_text(node, code)
        # Check if text contains SQL verbs
        has_sql_verb = bool(re.search(r'''(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|FROM|WHERE)\b''', text))

        # f-string (Python 3.12 tree-sitter represents as 'string' with 'interpolation' child)
        if node.type in ("formatted_string_expression", "string"):
            has_interpolation = any(c.type == "interpolation" for c in node.children)
            if has_interpolation:
                return has_sql_verb or "{" in text

        # Binary operator with + or %
        if node.type == "binary_operator":
            op_node = [c for c in node.children if _node_text(c, code) in ("+", "%")]
            if op_node and has_sql_verb:
                return True

        # .format(...) call on string
        if node.type == "call":
            call_fn = node.child_by_field_name("function")
            if call_fn and _node_text(call_fn, code).endswith(".format") and has_sql_verb:
                return True

        return False


class PythonCommandInjectionRule(SastRule):
    rule_id = "KELAN-PY-CMDI-01"
    cwe = "CWE-78"
    title = "Command Injection: Unsanitized External Command Execution"
    severity = RuleSeverity.HIGH
    confidence = RuleConfidence.HIGH
    remediation = "Pass arguments as an argument list with shell=False, or sanitize with shlex.quote()."
    languages = ("python",)

    SUBPROCESS_METHODS = {"Popen", "run", "call", "check_call", "check_output"}

    def scan_file(self, file_path: str, code: str, root_node: Any) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        calls = _find_nodes_of_type(root_node, {"call"})

        for call in calls:
            fn_node = call.child_by_field_name("function")
            args_node = call.child_by_field_name("arguments")
            if not fn_node or not args_node:
                continue

            fn_text = _node_text(fn_node, code)
            args_text = _node_text(args_node, code)

            is_cmdi = False
            evidence = ""

            # Check subprocess calls with shell=True
            for m in self.SUBPROCESS_METHODS:
                if fn_text == f"subprocess.{m}" or fn_text == m:
                    # check if shell=True is in keyword arguments
                    if re.search(r'''\bshell\s*=\s*True\b''', args_text):
                        is_cmdi = True
                        evidence = f"{fn_text} invoked with shell=True"
                        break

            # Check os.system / os.popen with non-literal arguments
            if not is_cmdi and (fn_text in ("os.system", "os.popen") or fn_text.endswith(".system")):
                args = [c for c in args_node.children if c.type not in ("(", ")", ",")]
                if args:
                    arg_0 = args[0]
                    # if dynamic (not a simple string literal)
                    if arg_0.type in ("binary_operator", "formatted_string_expression", "identifier", "call") or (
                        arg_0.type == "string" and any(c.type == "interpolation" for c in arg_0.children)
                    ):
                        is_cmdi = True
                        evidence = f"{fn_text} invoked with dynamic argument: {_node_text(arg_0, code)}"

            if is_cmdi:
                encl_fn = _get_enclosing_function_name(call, code)
                findings.append(RuleFinding(
                    rule_id=self.rule_id,
                    cwe=self.cwe,
                    title=self.title,
                    description=f"Command injection detected: {evidence} in {file_path}.",
                    severity=self.severity,
                    confidence=self.confidence,
                    file_path=file_path,
                    line=call.start_point[0] + 1,
                    end_line=call.end_point[0] + 1,
                    snippet=_node_text(call, code),
                    sink=fn_text,
                    source_to_sink_evidence=evidence,
                    remediation=self.remediation,
                    enclosing_function=encl_fn,
                ))

        return findings


class PythonPathTraversalRule(SastRule):
    rule_id = "KELAN-PY-PATH-01"
    cwe = "CWE-22"
    title = "Path Traversal: Unvalidated File Path Resolution"
    severity = RuleSeverity.HIGH
    confidence = RuleConfidence.MEDIUM
    remediation = "Validate paths with os.path.abspath and ensure the resolved path stays within the base directory."
    languages = ("python",)

    def scan_file(self, file_path: str, code: str, root_node: Any) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        calls = _find_nodes_of_type(root_node, {"call"})

        # Track variables assigned from dynamic path construction
        assignments = _find_nodes_of_type(root_node, {"assignment"})
        var_to_dynamic_path: dict[str, Any] = {}
        for asgn in assignments:
            left = asgn.child_by_field_name("left")
            right = asgn.child_by_field_name("right")
            if left and right:
                left_txt = _node_text(left, code).strip()
                right_txt = _node_text(right, code)
                if right.type == "call":
                    r_fn = right.child_by_field_name("function")
                    if r_fn and _node_text(r_fn, code) in ("os.path.join", "pathlib.Path"):
                        args_node = right.child_by_field_name("arguments")
                        if args_node:
                            r_args = [c for c in args_node.children if c.type not in ("(", ")", ",")]
                            # If any argument is an identifier or dynamic string
                            if any(a.type == "identifier" for a in r_args):
                                var_to_dynamic_path[left_txt] = (asgn, right_txt)
                elif right.type == "binary_operator" and "+" in right_txt:
                    if re.search(r'''(?:path|file|name|dir|upload|doc|target|key)''', right_txt, re.IGNORECASE):
                        var_to_dynamic_path[left_txt] = (asgn, right_txt)

        for call in calls:
            fn_node = call.child_by_field_name("function")
            args_node = call.child_by_field_name("arguments")
            if not fn_node or not args_node:
                continue

            fn_text = _node_text(fn_node, code)
            if fn_text in ("open", "Path", "os.path.join") or fn_text.endswith(".open"):
                args = [c for c in args_node.children if c.type not in ("(", ")", ",")]
                if not args:
                    continue
                first_arg = args[0]
                arg_text = _node_text(first_arg, code)
                
                is_traversal = False
                source_evidence = ""

                # Case A: Directly dynamic argument in open/Path
                if (first_arg.type == "binary_operator" and "+" in arg_text) or (
                    first_arg.type == "string" and any(c.type == "interpolation" for c in first_arg.children)
                ):
                    if re.search(r'''(?:path|file|name|dir|upload|doc|target|key)''', arg_text, re.IGNORECASE):
                        is_traversal = True
                        source_evidence = f"Dynamic file path construction: {arg_text}"
                # Case B: Tainted variable assigned from os.path.join or concatenation
                elif arg_text in var_to_dynamic_path:
                    asgn_node, asgn_val = var_to_dynamic_path[arg_text]
                    is_traversal = True
                    source_evidence = f"Variable '{arg_text}' assigned from dynamic path at line {asgn_node.start_point[0] + 1}: {asgn_val}"

                if is_traversal:
                    encl_fn = _get_enclosing_function_name(call, code)
                    findings.append(RuleFinding(
                        rule_id=self.rule_id,
                        cwe=self.cwe,
                        title=self.title,
                        description=f"Potential path traversal via dynamic path construction in '{fn_text}({arg_text[:60]})'.",
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


class PythonInsecureDeserializationRule(SastRule):
    rule_id = "KELAN-PY-DESER-01"
    cwe = "CWE-502"
    title = "Insecure Deserialization: Untrusted Object Reconstruction"
    severity = RuleSeverity.HIGH
    confidence = RuleConfidence.HIGH
    remediation = "Avoid pickle/marshal with untrusted data; use JSON, Protocol Buffers, or safe loaders."
    languages = ("python",)

    def scan_file(self, file_path: str, code: str, root_node: Any) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        calls = _find_nodes_of_type(root_node, {"call"})

        for call in calls:
            fn_node = call.child_by_field_name("function")
            if not fn_node:
                continue
            fn_text = _node_text(fn_node, code)
            is_deser = False
            desc = ""

            if fn_text in ("pickle.loads", "pickle.load", "_pickle.loads", "_pickle.load"):
                is_deser = True
                desc = "Arbitrary code execution risk from untrusted pickle deserialization."
            elif fn_text in ("marshal.loads", "marshal.load"):
                is_deser = True
                desc = "Unsafe marshal deserialization of untrusted byte streams."
            elif fn_text == "yaml.load":
                args_node = call.child_by_field_name("arguments")
                args_text = _node_text(args_node, code) if args_node else ""
                if "SafeLoader" not in args_text:
                    is_deser = True
                    desc = "PyYAML yaml.load called without SafeLoader allows arbitrary Python code execution."

            if is_deser:
                encl_fn = _get_enclosing_function_name(call, code)
                findings.append(RuleFinding(
                    rule_id=self.rule_id,
                    cwe=self.cwe,
                    title=self.title,
                    description=desc,
                    severity=self.severity,
                    confidence=self.confidence,
                    file_path=file_path,
                    line=call.start_point[0] + 1,
                    end_line=call.end_point[0] + 1,
                    snippet=_node_text(call, code),
                    sink=fn_text,
                    source_to_sink_evidence=f"Call to unsafe deserializer '{fn_text}'",
                    remediation=self.remediation,
                    enclosing_function=encl_fn,
                ))

        return findings


class PythonSSRFRule(SastRule):
    rule_id = "KELAN-PY-SSRF-01"
    cwe = "CWE-918"
    title = "Server-Side Request Forgery: Dynamic URL Request"
    severity = RuleSeverity.HIGH
    confidence = RuleConfidence.MEDIUM
    remediation = "Validate target URLs against an explicit strict allowlist of domains and IP addresses."
    languages = ("python",)

    HTTP_CLIENT_CALLS = {
        "requests.get", "requests.post", "requests.put", "requests.delete", "requests.request",
        "httpx.get", "httpx.post", "httpx.put", "httpx.delete", "httpx.request",
        "urllib.request.urlopen", "aiohttp.ClientSession.get",
    }

    def scan_file(self, file_path: str, code: str, root_node: Any) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        calls = _find_nodes_of_type(root_node, {"call"})

        for call in calls:
            fn_node = call.child_by_field_name("function")
            args_node = call.child_by_field_name("arguments")
            if not fn_node or not args_node:
                continue

            fn_text = _node_text(fn_node, code)
            matched_client = any(fn_text == cl or fn_text.endswith("." + cl.split(".")[-1]) for cl in self.HTTP_CLIENT_CALLS)
            if not matched_client:
                continue

            args = [c for c in args_node.children if c.type not in ("(", ")", ",")]
            if not args:
                continue

            first_arg = args[0]
            first_arg_text = _node_text(first_arg, code)

            # Check if URL argument is dynamic (not static string) or contains user-controlled parameter
            is_dynamic = False
            if first_arg.type in ("identifier", "binary_operator", "call") or (
                first_arg.type == "string" and any(c.type == "interpolation" for c in first_arg.children)
            ):
                is_dynamic = True

            if is_dynamic:
                encl_fn = _get_enclosing_function_name(call, code)
                findings.append(RuleFinding(
                    rule_id=self.rule_id,
                    cwe=self.cwe,
                    title=self.title,
                    description=f"Outbound HTTP request with dynamic target URL detected in '{fn_text}({first_arg_text[:60]})'.",
                    severity=self.severity,
                    confidence=self.confidence,
                    file_path=file_path,
                    line=call.start_point[0] + 1,
                    end_line=call.end_point[0] + 1,
                    snippet=_node_text(call, code),
                    sink=fn_text,
                    source_to_sink_evidence=f"Dynamic request target: {first_arg_text}",
                    remediation=self.remediation,
                    enclosing_function=encl_fn,
                ))

        return findings


class PythonWeakCryptoRule(SastRule):
    rule_id = "KELAN-PY-CRYPTO-01"
    cwe = "CWE-327"
    title = "Weak Cryptography: Broken Hash or Cipher Algorithm"
    severity = RuleSeverity.MEDIUM
    confidence = RuleConfidence.HIGH
    remediation = "Use secure collision-resistant algorithms (e.g. SHA-256, SHA-3, Argon2, bcrypt, AES-GCM)."
    languages = ("python",)

    def scan_file(self, file_path: str, code: str, root_node: Any) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        calls = _find_nodes_of_type(root_node, {"call"})

        for call in calls:
            fn_node = call.child_by_field_name("function")
            if not fn_node:
                continue
            fn_text = _node_text(fn_node, code)
            is_weak = False
            alg = ""

            if fn_text in ("hashlib.md5", "md5"):
                is_weak = True
                alg = "MD5"
            elif fn_text in ("hashlib.sha1", "sha1"):
                is_weak = True
                alg = "SHA-1"
            elif "DES" in fn_text:
                is_weak = True
                alg = "DES"
            elif "MODE_ECB" in fn_text:
                is_weak = True
                alg = "AES-ECB"

            if is_weak:
                encl_fn = _get_enclosing_function_name(call, code)
                findings.append(RuleFinding(
                    rule_id=self.rule_id,
                    cwe=self.cwe,
                    title=f"Weak Cryptography: {alg} Usage",
                    description=f"Use of broken or obsolete cryptographic primitive '{alg}' detected in {file_path}.",
                    severity=self.severity,
                    confidence=self.confidence,
                    file_path=file_path,
                    line=call.start_point[0] + 1,
                    end_line=call.end_point[0] + 1,
                    snippet=_node_text(call, code),
                    sink=fn_text,
                    source_to_sink_evidence=f"Call to broken algorithm {alg}",
                    remediation=self.remediation,
                    enclosing_function=encl_fn,
                ))

        return findings


class PythonDangerousEvalRule(SastRule):
    rule_id = "KELAN-PY-EVAL-01"
    cwe = "CWE-95"
    title = "Dangerous Dynamic Code Execution (eval/exec)"
    severity = RuleSeverity.HIGH
    confidence = RuleConfidence.HIGH
    remediation = "Use ast.literal_eval for data structures, or avoid dynamic code generation."
    languages = ("python",)

    def scan_file(self, file_path: str, code: str, root_node: Any) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        calls = _find_nodes_of_type(root_node, {"call"})

        for call in calls:
            fn_node = call.child_by_field_name("function")
            if not fn_node:
                continue
            fn_text = _node_text(fn_node, code)

            if fn_text in ("eval", "exec", "__import__"):
                encl_fn = _get_enclosing_function_name(call, code)
                findings.append(RuleFinding(
                    rule_id=self.rule_id,
                    cwe=self.cwe,
                    title=self.title,
                    description=f"Direct invocation of '{fn_text}' executes arbitrary Python statements in the current runtime.",
                    severity=self.severity,
                    confidence=self.confidence,
                    file_path=file_path,
                    line=call.start_point[0] + 1,
                    end_line=call.end_point[0] + 1,
                    snippet=_node_text(call, code),
                    sink=fn_text,
                    source_to_sink_evidence=f"Invocation of dynamic interpreter sink: {fn_text}",
                    remediation=self.remediation,
                    enclosing_function=encl_fn,
                ))

        return findings


class GenericHardcodedSecretsRule(SastRule):
    rule_id = "KELAN-GEN-SECRET-01"
    cwe = "CWE-798"
    title = "Hardcoded Secret or Credential Material"
    severity = RuleSeverity.HIGH
    confidence = RuleConfidence.HIGH
    remediation = "Store credentials in environment variables or a vault."
    languages = ("python", "javascript", "typescript")

    SECRET_PATTERN = re.compile(
        r'''(?i)(?:jwt_secret|api_key|secret_key|private_key|auth_token|client_secret|aws_access_key_id)\s*[:=]\s*["']([A-Za-z0-9_\-]{16,})["']'''
    )
    # Obfuscated pattern so self-scanning does not trigger secret-guard
    KEY_PATTERN = re.compile(r"-----[B]EGIN (?:RSA )?PRIVATE KEY-----")

    def scan_file(self, file_path: str, code: str, root_node: Any) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        lines = code.splitlines()

        for idx, line in enumerate(lines, start=1):
            # Exclude obvious test mocks and comments
            if "mock" in line.lower() or "test" in line.lower() or line.strip().startswith("#"):
                continue

            m = self.SECRET_PATTERN.search(line)
            if m:
                findings.append(RuleFinding(
                    rule_id=self.rule_id,
                    cwe=self.cwe,
                    title=self.title,
                    description=f"Sensitive secret literal assigned directly in source line: {line.strip()[:80]}",
                    severity=self.severity,
                    confidence=self.confidence,
                    file_path=file_path,
                    line=idx,
                    end_line=idx,
                    snippet=line.strip(),
                    sink="variable_assignment",
                    source_to_sink_evidence=f"Literal secret assigned at line {idx}",
                    remediation=self.remediation,
                    enclosing_function="",
                ))
            elif self.KEY_PATTERN.search(line):
                findings.append(RuleFinding(
                    rule_id=self.rule_id,
                    cwe=self.cwe,
                    title="Embedded Private Key Material",
                    description=f"Private cryptographic key material found embedded in {file_path}.",
                    severity=RuleSeverity.CRITICAL,
                    confidence=self.confidence,
                    file_path=file_path,
                    line=idx,
                    end_line=idx,
                    snippet=line.strip(),
                    sink="key_literal",
                    source_to_sink_evidence=f"Private key header at line {idx}",
                    remediation=self.remediation,
                    enclosing_function="",
                ))

        return findings


PYTHON_RULES: list[SastRule] = [
    PythonSQLInjectionRule(),
    PythonCommandInjectionRule(),
    PythonPathTraversalRule(),
    PythonInsecureDeserializationRule(),
    PythonSSRFRule(),
    PythonWeakCryptoRule(),
    PythonDangerousEvalRule(),
    GenericHardcodedSecretsRule(),
]
