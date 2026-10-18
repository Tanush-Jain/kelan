
import json

SCANNER_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "has_security_flaw": {
            "type": "boolean",
            "description": (
                "True only when a clear technical root cause shows the code "
                "fails to validate input or manage state safely."
            ),
        },
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "cwe_id": {
                        "type": "string",
                        "description": "e.g. CWE-89, CWE-79, CWE-20",
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    },
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "root_cause_analysis": {"type": "string"},
                    "remediation": {"type": "string"},
                },
                "required": [
                    "cwe_id", "severity", "title", "description",
                    "root_cause_analysis", "remediation",
                ],
                "additionalProperties": False,
            },
        },
    },
    "required": ["has_security_flaw", "findings"],
    "additionalProperties": False,
}


SCANNER_SYSTEM_PROMPT = (
    "You are a defensive static code auditor. Review the provided code chunk "
    "for security weaknesses and implementation flaws. If you cannot establish "
    "a clear technical root cause showing how the code fails to validate input "
    "or manage state safely, set has_security_flaw to false. Ignore code "
    "formatting, stylistic preferences, and general linting rules."
)


def build_scan_prompt(chunk: dict) -> str:

    return (
        "Analyze the following code chunk for security weaknesses.\n\n"
        f"file_path: {chunk.get('file_path', 'unknown')}\n"
        f"type: {chunk.get('type', 'unknown')}\n"
        f"start_line: {chunk.get('start_line')}\n"
        f"end_line: {chunk.get('end_line')}\n\n"
        "```\n"
        f"{chunk.get('content', '')}\n"
        "```\n\n"
        "Respond ONLY with a single valid JSON object matching this schema:\n"
        f"{json.dumps(SCANNER_JSON_SCHEMA, indent=2)}\n"
        "No markdown fences, no commentary, no code — JSON only."
    )