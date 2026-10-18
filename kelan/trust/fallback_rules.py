from kelan.ai.engine import _fallback

class FallbackRulesEngine:
    async def evaluate(self, ctx: dict) -> dict:
        trust_verdict = _fallback(ctx)
        return {
            "verdict": trust_verdict.verdict.value,
            "confidence": trust_verdict.confidence,
            "reason": trust_verdict.reason,
        }
