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
            args_node = call.child_by_field_name("arguments")
            if not fn_node:
                continue
            fn_text = _node_text(fn_node, code)
            args_text = _node_text(args_node, code) if args_node else ""
            encl_fn = _get_enclosing_function_name(call, code)

            # If used for password hashing, let PythonWeakPasswordHashRule (CWE-759) handle it
            if re.search(r'''(?i)(password|passwd|pwd|passphrase)''', args_text) or re.search(r'''(?i)(password|passwd|pwd|passphrase)''', encl_fn):
                continue

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

            # If used for password hashing, let PythonWeakPasswordHashRule (CWE-759) handle it
            if is_weak and call.parent and re.search(r'''(?i)(password|passwd|pwd|passphrase)''', _node_text(call.parent, code)):
                continue

            # If used for password hashing, let PythonWeakPasswordHashRule (CWE-759) handle it
            if is_weak and call.parent and re.search(r'''(?i)(password|passwd|pwd|passphrase)''', _node_text(call.parent, code)):
                continue

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


class PythonXXERule(SastRule):
    rule_id = "KELAN-PY-XXE-01"
    cwe = "CWE-611"
    title = "XML External Entity (XXE) Injection: Insecure Entity Resolution"
    severity = RuleSeverity.HIGH
    confidence = RuleConfidence.HIGH
    remediation = "Disable external entity resolution: use defusedxml or configure XMLParser(resolve_entities=False)."
    languages = ("python",)

    XXE_SINKS = {
        "xml.etree.ElementTree.parse", "xml.etree.ElementTree.fromstring",
        "ET.parse", "ET.fromstring",
        "xml.dom.minidom.parse", "xml.dom.minidom.parseString",
        "minidom.parse", "minidom.parseString",
        "lxml.etree.parse", "lxml.etree.fromstring", "lxml.etree.XMLParser",
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
            matched = any(fn_text == s or fn_text.endswith("." + s.split(".")[-1]) for s in self.XXE_SINKS)
            if not matched:
                continue

            args_text = _node_text(args_node, code)
            # If lxml with resolve_entities=False, safe!
            if "resolve_entities=False" in args_text:
                continue

            # If defusedxml is imported, safe!
            if re.search(r'''\b(?:import\s+defusedxml|from\s+defusedxml)\b''', code):
                continue

            encl_fn = _get_enclosing_function_name(call, code)
            findings.append(RuleFinding(
                rule_id=self.rule_id,
                cwe=self.cwe,
                title=self.title,
                description=f"Insecure XML parsing sink '{fn_text}' vulnerable to XXE external entity resolution.",
                severity=self.severity,
                confidence=self.confidence,
                file_path=file_path,
                line=call.start_point[0] + 1,
                end_line=call.end_point[0] + 1,
                snippet=_node_text(call, code),
                sink=fn_text,
                source_to_sink_evidence=f"Call to XML parser {fn_text} without defusedxml or resolve_entities=False",
                remediation=self.remediation,
                enclosing_function=encl_fn,
            ))
        return findings


class PythonInsecureRandomRule(SastRule):
    rule_id = "KELAN-PY-RAND-01"
    cwe = "CWE-330"
    title = "Insecure Randomness: Pseudo-Random Number Generator Used for Security Secrets"
    severity = RuleSeverity.MEDIUM
    confidence = RuleConfidence.HIGH
    remediation = "Use the secrets module (e.g. secrets.token_hex(), secrets.token_urlsafe()) for cryptographic keys and tokens."
    languages = ("python",)

    RANDOM_CALLS = {
        "random.random", "random.randint", "random.choice", "random.choices",
        "random.randrange", "random.sample", "random.getrandbits"
    }
    SECURITY_WORDS = re.compile(r'''(?i)(token|secret|key|password|passwd|session|auth|nonce|csrf|salt|pin)''')

    def scan_file(self, file_path: str, code: str, root_node: Any) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        assignments = _find_nodes_of_type(root_node, {"assignment"})

        for asgn in assignments:
            left = asgn.child_by_field_name("left")
            right = asgn.child_by_field_name("right")
            if not left or not right:
                continue
            left_txt = _node_text(left, code).strip()
            right_txt = _node_text(right, code)

            if self.SECURITY_WORDS.search(left_txt):
                if any(rc in right_txt for rc in self.RANDOM_CALLS):
                    encl_fn = _get_enclosing_function_name(asgn, code)
                    findings.append(RuleFinding(
                        rule_id=self.rule_id,
                        cwe=self.cwe,
                        title=self.title,
                        description=f"Standard PRNG 'random' used to generate sensitive security value '{left_txt}'.",
                        severity=self.severity,
                        confidence=self.confidence,
                        file_path=file_path,
                        line=asgn.start_point[0] + 1,
                        end_line=asgn.end_point[0] + 1,
                        snippet=_node_text(asgn, code),
                        sink=f"assignment:{left_txt}",
                        source_to_sink_evidence=f"Variable '{left_txt}' assigned from random generator: {right_txt[:80]}",
                        remediation=self.remediation,
                        enclosing_function=encl_fn,
                    ))
        return findings


class PythonWeakPasswordHashRule(SastRule):
    rule_id = "KELAN-PY-PASSHASH-01"
    cwe = "CWE-759"
    title = "Weak Password Hashing: Fast or Non-Adaptive Digest Used for Passwords"
    severity = RuleSeverity.HIGH
    confidence = RuleConfidence.HIGH
    remediation = "Use slow, adaptive password hashing algorithms like bcrypt, argon2id, or hashlib.pbkdf2_hmac with salt."
    languages = ("python",)

    HASH_FUNCS = {"hashlib.md5", "md5", "hashlib.sha1", "sha1"}
    PWD_WORDS = re.compile(r'''(?i)(password|passwd|pwd|passphrase)''')

    def scan_file(self, file_path: str, code: str, root_node: Any) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        calls = _find_nodes_of_type(root_node, {"call"})

        for call in calls:
            fn_node = call.child_by_field_name("function")
            args_node = call.child_by_field_name("arguments")
            if not fn_node or not args_node:
                continue
            fn_text = _node_text(fn_node, code)
            if fn_text not in self.HASH_FUNCS:
                continue

            args_text = _node_text(args_node, code)
            encl_fn = _get_enclosing_function_name(call, code)

            is_pass_hash = bool(self.PWD_WORDS.search(args_text) or self.PWD_WORDS.search(encl_fn))
            if not is_pass_hash and call.parent and call.parent.type == "assignment":
                left = call.parent.child_by_field_name("left")
                if left and self.PWD_WORDS.search(_node_text(left, code)):
                    is_pass_hash = True

            if is_pass_hash:
                findings.append(RuleFinding(
                    rule_id=self.rule_id,
                    cwe=self.cwe,
                    title=self.title,
                    description=f"Fast hash function '{fn_text}' used for password hashing without salt or adaptive work factor.",
                    severity=self.severity,
                    confidence=self.confidence,
                    file_path=file_path,
                    line=call.start_point[0] + 1,
                    end_line=call.end_point[0] + 1,
                    snippet=_node_text(call, code),
                    sink=fn_text,
                    source_to_sink_evidence=f"Call to {fn_text} hashing password data: {args_text[:80]}",
                    remediation=self.remediation,
                    enclosing_function=encl_fn,
                ))
        return findings


class PythonSensitiveLoggingRule(SastRule):
    rule_id = "KELAN-PY-LOG-01"
    cwe = "CWE-532"
    title = "Sensitive Data Exposure in Logging or Output"
    severity = RuleSeverity.LOW
    confidence = RuleConfidence.MEDIUM
    remediation = "Sanitize or mask credentials, tokens, and personal secrets before writing to logs."
    languages = ("python",)

    LOG_CALLS = {
        "logging.info", "logging.debug", "logging.warning", "logging.error", "logging.critical",
        "logger.info", "logger.debug", "logger.warning", "logger.error", "logger.critical",
        "print"
    }
    SENSITIVE_WORDS = re.compile(r'''(?i)\b(password|passwd|secret|api_key|token|auth_token|access_token|private_key|credit_card)\b''')

    def scan_file(self, file_path: str, code: str, root_node: Any) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        calls = _find_nodes_of_type(root_node, {"call"})

        for call in calls:
            fn_node = call.child_by_field_name("function")
            args_node = call.child_by_field_name("arguments")
            if not fn_node or not args_node:
                continue
            fn_text = _node_text(fn_node, code)
            matched = any(fn_text == s or fn_text.endswith("." + s.split(".")[-1]) for s in self.LOG_CALLS)
            if not matched:
                continue

            args_text = _node_text(args_node, code)
            if self.SENSITIVE_WORDS.search(args_text) and not any(k in args_text.lower() for k in ("redacted", "masked", "***")):
                has_var = bool(re.search(r'''\{[^}]*(?:password|passwd|secret|key|token)[^}]*\}''', args_text, re.IGNORECASE))
                if not has_var:
                    args = [c for c in args_node.children if c.type not in ("(", ")", ",")]
                    has_var = any(a.type == "identifier" and self.SENSITIVE_WORDS.search(_node_text(a, code)) for a in args)

                if has_var:
                    encl_fn = _get_enclosing_function_name(call, code)
                    findings.append(RuleFinding(
                        rule_id=self.rule_id,
                        cwe=self.cwe,
                        title=self.title,
                        description=f"Sensitive variable logged or printed via '{fn_text}'.",
                        severity=self.severity,
                        confidence=self.confidence,
                        file_path=file_path,
                        line=call.start_point[0] + 1,
                        end_line=call.end_point[0] + 1,
                        snippet=_node_text(call, code),
                        sink=fn_text,
                        source_to_sink_evidence=f"Sensitive data passed to logging sink: {args_text[:80]}",
                        remediation=self.remediation,
                        enclosing_function=encl_fn,
                    ))
        return findings


class PythonMissingAuthRule(SastRule):
    rule_id = "KELAN-PY-NOAUTH-01"
    cwe = "CWE-284"
    title = "Missing Authorization / Authentication Check on Sensitive Route (Advisory)"
    severity = RuleSeverity.LOW
    confidence = RuleConfidence.LOW
    remediation = "Enforce authentication and role-based access checks (e.g., FastAPI Depends(get_current_user) or Flask @login_required)."
    languages = ("python",)

    ROUTE_DECORATORS = re.compile(r'''(?i)@(?:app|router|bp)\.(?:route|get|post|put|delete|patch)''')
    SENSITIVE_NAMES = re.compile(r'''(?i)(admin|delete|update|role|manage|account|user_id|billing)''')
    AUTH_INDICATORS = re.compile(r'''(?i)(login_required|jwt_required|auth_required|roles_accepted|Depends\(|permission)''')

    def scan_file(self, file_path: str, code: str, root_node: Any) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        fn_defs = _find_nodes_of_type(root_node, {"function_definition", "async_function_definition"})

        for fn_node in fn_defs:
            name_node = fn_node.child_by_field_name("name")
            if not name_node:
                continue
            fn_name = _node_text(name_node, code)

            decorators: list[str] = []
            parent = fn_node.parent
            if parent and parent.type == "decorated_definition":
                for child in parent.children:
                    if child.type == "decorator":
                        decorators.append(_node_text(child, code))

            decor_text = " ".join(decorators)
            if not self.ROUTE_DECORATORS.search(decor_text):
                continue

            params_node = fn_node.child_by_field_name("parameters")
            params_text = _node_text(params_node, code) if params_node else ""
            is_sensitive = bool(self.SENSITIVE_NAMES.search(fn_name) or self.SENSITIVE_NAMES.search(decor_text))
            if not is_sensitive:
                continue

            has_auth = bool(self.AUTH_INDICATORS.search(decor_text) or self.AUTH_INDICATORS.search(params_text))
            if not has_auth:
                findings.append(RuleFinding(
                    rule_id=self.rule_id,
                    cwe=self.cwe,
                    title=self.title,
                    description=(
                        f"Advisory: Sensitive endpoint '{fn_name}' appears to lack authentication or authorization checks. "
                        "Note: This is a low-confidence advisory rule intended for manual review."
                    ),
                    severity=self.severity,
                    confidence=self.confidence,
                    file_path=file_path,
                    line=fn_node.start_point[0] + 1,
                    end_line=fn_node.end_point[0] + 1,
                    snippet=_node_text(fn_node, code).split("\n")[0],
                    sink="route_decorator",
                    source_to_sink_evidence=f"Route '{decor_text}' has no detected auth dependency or decorator",
                    remediation=self.remediation,
                    enclosing_function=fn_name,
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
    PythonXXERule(),
    PythonInsecureRandomRule(),
    PythonWeakPasswordHashRule(),
    PythonSensitiveLoggingRule(),
    PythonMissingAuthRule(),
]
