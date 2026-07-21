"""
Behavior Correlation Engine — AgentBound Phase 1.

Correlates declared AgentIntent against observed kernel events (file opens, connects, execs).
Reuses OllamaClient, _parse, CircuitBreaker, and TrustVerdict from kelan.ai without reimplementing retry or parsing logic.
"""

from __future__ import annotations
import time
from dataclasses import dataclass
from typing import Optional
import structlog

from kelan.ai.ollama_client import OllamaClient, TrustVerdict, Verdict, _parse
from kelan.ai.engine import CircuitBreaker
from .intent_extractor import AgentIntent
from .skill_loader import load_agentic_security_skills, format_skills_for_prompt

log = structlog.get_logger()


@dataclass
class BehaviorVerdict:
    verdict:             Verdict
    confidence:          float
    reason:              str
    divergence_detected: bool
    latency_ms:          float = 0.0

    def to_dict(self) -> dict:
        return {
            "verdict":             self.verdict.value,
            "confidence":          round(self.confidence, 3),
            "reason":              self.reason,
            "divergence_detected": self.divergence_detected,
            "latency_ms":          round(self.latency_ms, 1),
        }


def build_behavior_prompt(intent: AgentIntent, events: list[dict]) -> str:
    """
    Construct correlation prompt for LLM evaluation.
    
    EXPLICITLY REUSES skill_loader.py to ground evaluation against AI/Agentic Security domain.
    """
    # Skill loader call - grounds prompt in agentic security domain
    skills_text = format_skills_for_prompt(load_agentic_security_skills())

    event_summary = []
    for idx, ev in enumerate(events, 1):
        kind = ev.get("kind", ev.get("type", "unknown"))
        target = ev.get("path", ev.get("dest_host", ev.get("binary", "unknown")))
        event_summary.append(f"  Event {idx}: kind={kind}, target={target}")

    events_str = "\n".join(event_summary) if event_summary else "  None recorded"

    prompt = f"""You are Kelan AgentBound Security Evaluator.

{skills_text}

=== DECLARED AGENT INTENT ===
PID: {intent.pid}
Agent Type: {intent.agent_type}
Declared Path Scope: {intent.declared_paths if intent.declared_paths else 'Unrestricted / None Specified'}
Declared Task:
{intent.declared_task if intent.declared_task else 'No explicit task file provided'}

=== OBSERVED KERNEL EVENTS ===
{events_str}

=== EVALUATION INSTRUCTION ===
Analyze whether the observed kernel events fall inside the declared scope.
Does this observed action represent a real scope divergence or is it benign?

Return ONLY a JSON object with:
- "verdict": "ALLOW" (in-scope/benign), "DENY" (unauthorized divergence), or "MONITOR" (suspicious)
- "confidence": float between 0.0 and 1.0
- "reason": one-sentence explanation of verdict
"""
    return prompt


def _deterministic_behavior_fallback(intent: AgentIntent, events: list[dict]) -> BehaviorVerdict:
    """Fallback deterministic rules when LLM inference is unavailable."""
    sensitive_prefixes = ("/etc/ssh/", "/etc/shadow", "/etc/passwd", "/root/.ssh", "/root/.aws")

    for ev in events:
        target = str(ev.get("path", ev.get("dest_host", ev.get("binary", ""))))
        target_norm = target.replace("~", "/root")

        # Check sensitive paths
        if any(target_norm.startswith(sp) or target.startswith(sp) for sp in sensitive_prefixes) or ".aws" in target or ".ssh" in target:
            return BehaviorVerdict(
                verdict=Verdict.DENY,
                confidence=0.95,
                reason=f"Action targeting restricted sensitive path '{target}' outside declared intent scope.",
                divergence_detected=True,
            )

        # Check against declared path scope if non-empty
        if intent.declared_paths:
            if not any(target.startswith(p) or target_norm.startswith(p) for p in intent.declared_paths):
                return BehaviorVerdict(
                    verdict=Verdict.DENY,
                    confidence=0.90,
                    reason=f"Observed action '{target}' diverges from declared scope {intent.declared_paths}.",
                    divergence_detected=True,
                )

    return BehaviorVerdict(
        verdict=Verdict.ALLOW,
        confidence=0.85,
        reason="Observed kernel events fall within declared agent scope.",
        divergence_detected=False,
    )


class BehaviorEngine:
    """Correlates agent declared intent against observed kernel events using OllamaClient."""

    def __init__(
        self,
        ollama: Optional[OllamaClient] = None,
        threshold: int = 3,
        recovery: int = 30,
    ):
        if ollama is None:
            from kelan.config import get_settings
            settings = get_settings()
            ollama = OllamaClient(
                endpoint=settings.ollama_endpoint,
                model=settings.ollama_model,
                timeout=settings.ollama_timeout,
                temperature=settings.ollama_temperature,
                max_tokens=settings.ollama_max_tokens,
            )
        self.ollama = ollama
        self.cb = CircuitBreaker(threshold, recovery)

    async def evaluate(self, intent: AgentIntent, events: list[dict]) -> BehaviorVerdict:
        """Evaluate intent vs observed events using LLM inference with fallback."""
        if not self.cb.allow:
            return _deterministic_behavior_fallback(intent, events)

        prompt = build_behavior_prompt(intent, events)

        try:
            t0 = time.monotonic()
            raw_response = await self.ollama.raw_generate(prompt)
            latency_ms = (time.monotonic() - t0) * 1000.0

            # Reuse existing 3-strategy JSON parser from ollama_client
            tv: TrustVerdict = _parse(raw_response)
            self.cb.success()

            divergence = tv.verdict in (Verdict.DENY, Verdict.MONITOR)
            return BehaviorVerdict(
                verdict=tv.verdict,
                confidence=tv.confidence,
                reason=tv.reason,
                divergence_detected=divergence,
                latency_ms=latency_ms,
            )
        except Exception as exc:
            log.warning("behavior_engine_ollama_fallback", error=str(exc))
            self.cb.failure()
            return _deterministic_behavior_fallback(intent, events)
