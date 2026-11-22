# ══ Kelan SAST — Go AST Deterministic Rules ═════════════════════════════════════
# License: MIT License (https://opensource.org/licenses/MIT)
# Copyright (c) 2026 Tanush Jain / Kelan Community

from __future__ import annotations

import re
from typing import Any

from kelan.sast.rules.base import RuleConfidence, RuleFinding, RuleSeverity, SastRule
from kelan.sast.rules.python_rules import GenericHardcodedSecretsRule, _find_nodes_of_type, _node_text


def _get_enclosing_go_function(node: Any, code: str) -> str:
    cur = node
    while cur is not None:
        if cur.type in ("function_declaration", "method_declaration"):
            name_node = cur.child_by_field_name("name")
            if name_node:
                return _node_text(name_node, code)
        cur = cur.parent
    return ""


class GoSQLInjectionRule(SastRule):
    rule_id = "KELAN-GO-SQLI-01"
    cwe = "CWE-89"
    title = "SQL Injection: Unparameterized Query Construction"
    severity = RuleSeverity.CRITICAL
    confidence = RuleConfidence.HIGH
    remediation = "Use parameterized queries with placeholder syntax (e.g. db.Query('SELECT * FROM tbl WHERE id = ?', id))."
    languages = ("go",)

    QUERY_METHODS = {"Query", "QueryRow", "Exec", "QueryContext", "QueryRowContext", "ExecContext"}

    def scan_file(self, file_path: str, code: str, root_node: Any) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        calls = _find_nodes_of_type(root_node, {"call_expression"})

        # Track variable assignments from dynamic SQL or Sprintf
        var_to_dynamic_sql: dict[str, Any] = {}
        short_vars = _find_nodes_of_type(root_node, {"short_var_declaration", "assignment_statement"})
        for sv in short_vars:
            left_node = sv.child_by_field_name("left")
            right_node = sv.child_by_field_name("right")
            if not left_node or not right_node:
                continue
            left_txt = _node_text(left_node, code).strip()
            right_txt = _node_text(right_node, code)
            has_sql_verb = bool(re.search(r'''(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|FROM|WHERE)\b''', right_txt))
            if has_sql_verb and ("Sprintf" in right_txt or "+" in right_txt):
                var_to_dynamic_sql[left_txt] = (sv, right_txt)

        for call in calls:
            fn_node = call.child_by_field_name("function")
            args_node = call.child_by_field_name("arguments")
            if not fn_node or not args_node:
                continue
            fn_text = _node_text(fn_node, code)
            is_query = any(fn_text.endswith("." + m) or fn_text == m for m in self.QUERY_METHODS)
            if not is_query:
                continue

            args = [c for c in args_node.children if c.type not in ("(", ")", ",")]
            if not args:
                continue

            # First argument or second if context is passed
            target_arg = args[0]
            if len(args) > 1 and "ctx" in _node_text(args[0], code).lower():
                target_arg = args[1]
            arg_text = _node_text(target_arg, code)

            is_sqli = False
            evidence = ""
            has_sql_verb = bool(re.search(r'''(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|FROM|WHERE)\b''', arg_text))

            if ("fmt.Sprintf" in arg_text or "+" in arg_text) and has_sql_verb:
                is_sqli = True
                evidence = f"Dynamic query formatted in call: {arg_text[:80]}"
            elif arg_text in var_to_dynamic_sql:
                asgn_node, asgn_val = var_to_dynamic_sql[arg_text]
                is_sqli = True
                evidence = f"Variable '{arg_text}' assigned dynamic SQL at line {asgn_node.start_point[0] + 1}: {asgn_val[:80]}"

            if is_sqli:
                encl_fn = _get_enclosing_go_function(call, code)
                findings.append(RuleFinding(
                    rule_id=self.rule_id,
                    cwe=self.cwe,
                    title=self.title,
                    description=f"Potential SQL injection detected via dynamic query in '{fn_text}' in {file_path}.",
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


class GoCommandInjectionRule(SastRule):
    rule_id = "KELAN-GO-CMDI-01"
    cwe = "CWE-78"
    title = "Command Injection: Unsanitized External Command Execution"
    severity = RuleSeverity.HIGH
    confidence = RuleConfidence.HIGH
    remediation = "Pass command arguments directly to exec.Command rather than invoking shell interpreters with -c."
    languages = ("go",)

    def scan_file(self, file_path: str, code: str, root_node: Any) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        calls = _find_nodes_of_type(root_node, {"call_expression"})

        for call in calls:
            fn_node = call.child_by_field_name("function")
            args_node = call.child_by_field_name("arguments")
            if not fn_node or not args_node:
                continue
            fn_text = _node_text(fn_node, code)
            if fn_text in ("exec.Command", "exec.CommandContext") or fn_text.endswith(".Command") or fn_text.endswith(".CommandContext"):
                args = [c for c in args_node.children if c.type not in ("(", ")", ",")]
                # exec.Command("sh", "-c", input) or exec.CommandContext(ctx, "sh", "-c", input)
                shell_idx = 0
                if fn_text.endswith("CommandContext") and len(args) > 1:
                    shell_idx = 1

                if len(args) > shell_idx + 2:
                    shell_arg = _node_text(args[shell_idx], code).strip('"\'')
                    flag_arg = _node_text(args[shell_idx + 1], code).strip('"\'')
                    if shell_arg in ("sh", "bash", "/bin/sh", "/bin/bash", "cmd", "cmd.exe") and flag_arg in ("-c", "/c", "/C"):
                        cmd_arg = _node_text(args[shell_idx + 2], code)
                        encl_fn = _get_enclosing_go_function(call, code)
                        findings.append(RuleFinding(
                            rule_id=self.rule_id,
                            cwe=self.cwe,
                            title=self.title,
                            description=f"Command injection sink: '{fn_text}' executes arbitrary command string via shell interpreter.",
                            severity=self.severity,
                            confidence=self.confidence,
                            file_path=file_path,
                            line=call.start_point[0] + 1,
                            end_line=call.end_point[0] + 1,
                            snippet=_node_text(call, code),
                            sink=fn_text,
                            source_to_sink_evidence=f"Call to {fn_text} with shell '{shell_arg} {flag_arg}' and dynamic argument: {cmd_arg[:60]}",
                            remediation=self.remediation,
                            enclosing_function=encl_fn,
                        ))

        return findings


GO_RULES: list[SastRule] = [
    GoSQLInjectionRule(),
    GoCommandInjectionRule(),
    GenericHardcodedSecretsRule(),
]
