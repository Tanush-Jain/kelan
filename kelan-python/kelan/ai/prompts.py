"""
Attack detection prompts for Ollama.
Centralised here so prompt engineering changes don't require touching engine code.

Model dispatch:
  qwen2.5:3b  → <|im_start|>/<|im_end|> chat-template tokens  ← CURRENT
  gemma3:9b   → uncomment the gemma3 block when GPU is ready   ← FUTURE
  others      → generic SYSTEM_PROMPT format                   ← FALLBACK

To switch models: change OLLAMA_MODEL in .env, restart server.
"""

SYSTEM_PROMPT = """You are the Kelan Security AI Trust Engine — a cybersecurity expert embedded in a zero-trust network system.

Evaluate the JSON session context and return a single-line JSON verdict.

━━━ DENY — always block ━━━
• SYN flood / UDP flood  (syn_rate_per_second > 50 OR udp_rate_per_second > 200)
• Port scan              (ports_probed > 100 unique ports)
• Sybil burst            (enrollment_count_from_ip > 10 in 5 s window)
• Invalid crypto sig     (signature all-zeros or wrong length = spoofing)
• Brute force auth       (failed_auth_attempts > 20)
• Lateral movement       (internal_ip_scanning = true)
• Known exploit pattern  (shellshock / log4j / etc. in payload)
• Data exfiltration      (unusual_large_outbound = true)

━━━ MONITOR — watch, don't block ━━━
• Anomaly score 0.3–0.7
• Unknown entity with no prior history
• Unusual geographic timing but no hard indicator

━━━ ALLOW — permit ━━━
• Normal enrollment, clean history, low anomaly (<0.3)
• Known entity with consistent patterns
• Expected API access with valid ML-KEM ciphertext

RULES:
• confidence < 0.5 → override verdict to MONITOR regardless
• reason must be ≤ 100 characters

Respond with ONLY valid JSON — no markdown, no explanation:
{"verdict":"DENY","confidence":0.95,"reason":"brief reason here"}"""


def build_evaluation_prompt(session: dict) -> str:
    """Build the full prompt for a session evaluation.

    Dispatches to a model-specific template based on OLLAMA_MODEL env var.
    To switch models: change OLLAMA_MODEL in .env, restart the server.
    This function auto-selects the correct prompt format.
    """
    import json
    import os

    model = os.getenv("OLLAMA_MODEL", "qwen2.5:3b").lower()
    session_json = json.dumps(session, indent=2, default=str)

    # ─────────────────────────────────────────────────────────────────────
    # CURRENT: qwen2.5:3b prompt (CPU-friendly, chat-template tokens)
    # These <|im_start|>/<|im_end|> tokens tell qwen to output ONLY JSON.
    # ─────────────────────────────────────────────────────────────────────
    if "qwen" in model or "3b" in model:
        return (
            "<|im_start|>system\n"
            "You are the Kelan Security AI Trust Engine — a cybersecurity expert "
            "embedded in a zero-trust network system.\n"
            "Output ONLY a JSON object. No explanation. No markdown. No code blocks. "
            "Raw JSON only.\n\n"
            "Rules:\n"
            "- DENY:    SYN/UDP flood, port scan>100, sybil burst>10, "
            "brute-force>20, exploit pattern\n"
            "- MONITOR: anomaly present but not severe, unknown entity, "
            "new enrollment\n"
            "- ALLOW:   clean session, known entity, low anomaly\n"
            "- confidence<0.5 → override to MONITOR\n"
            "- reason ≤ 100 chars\n"
            "<|im_end|>\n"
            "<|im_start|>user\n"
            f"Classify this network session:\n{session_json}\n\n"
            '{"verdict":"ALLOW","confidence":0.9,"reason":"brief reason"}\n'
            "<|im_end|>\n"
            "<|im_start|>assistant\n"
        )

    # ─────────────────────────────────────────────────────────────────────
    # FUTURE: gemma3:9b / gemma3:27b — uncomment when GPU is ready
    # Step 1: ollama pull gemma3:9b   (on GPU machine)
    # Step 2: set OLLAMA_MODEL=gemma3:9b in .env
    # Step 3: also increase OLLAMA_TIMEOUT_SECS=15 for larger model
    # Step 4: restart server — this block activates automatically
    # ─────────────────────────────────────────────────────────────────────
    # if "gemma3" in model:
    #     return (
    #         "You are the Kelan Security AI Trust Engine.\n"
    #         "Analyze this session and respond ONLY with valid JSON.\n"
    #         "No markdown. No explanation.\n\n"
    #         f"Session:\n{session_json}\n\n"
    #         "Rules:\n"
    #         "- DENY:    SYN/UDP flood, port scan, sybil, brute-force, exploit\n"
    #         "- MONITOR: minor anomalies or unknown entity\n"
    #         "- ALLOW:   clean, known entity, low anomaly (<0.3)\n"
    #         "- confidence<0.5 → override to MONITOR\n\n"
    #         'Respond with exactly: {"verdict":"ALLOW","confidence":0.95,"reason":"explanation"}\n'
    #         "verdict = ALLOW, DENY, or MONITOR only\n"
    #         "confidence = 0.0 to 1.0 only"
    #     )

    # ─────────────────────────────────────────────────────────────────────
    # DEFAULT: generic format (works for most models)
    # ─────────────────────────────────────────────────────────────────────
    return f"""{SYSTEM_PROMPT}

Session context:
{session_json}

JSON verdict:"""


# ── Quick sanity-check prompt ─────────────────────────────────────────────────
VERIFY_PROMPT = """Reply with exactly this JSON and nothing else:
{"status":"ok","model":"kelan-trust-engine","role":"security-classifier"}"""
