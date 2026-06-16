"""
Ollama Client — gemma4:latest local inference.
Pure async Python. Zero external API calls.
"""
import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import httpx
import structlog
from tenacity import (
    retry, stop_after_attempt,
    wait_exponential, retry_if_exception_type,
)
from .prompts import SYSTEM_PROMPT, build_prompt

log = structlog.get_logger()


class Verdict(str, Enum):
    ALLOW   = "ALLOW"
    DENY    = "DENY"
    MONITOR = "MONITOR"


@dataclass
class TrustVerdict:
    verdict:    Verdict
    confidence: float
    reason:     str
    latency_ms: float        = 0.0
    raw:        str          = field(default="", repr=False)
    from_cache: bool         = False

    def to_dict(self) -> dict:
        return {
            "verdict":    self.verdict.value,
            "confidence": round(self.confidence, 3),
            "reason":     self.reason,
            "reasoning":  self.reason,
            "latency_ms": round(self.latency_ms, 1),
        }

    @property
    def is_allow(self) -> bool:
        return self.verdict == Verdict.ALLOW and self.confidence >= 0.5


def _parse(raw: str) -> TrustVerdict:
    """Three-strategy parser for Ollama's response."""
    text = raw.strip()

    # ── Strategy 1: direct JSON 
    for candidate in [text, text.split("```json")[-1].split("```")[0].strip()]:
        try:
            d = json.loads(candidate)
            v = str(d.get("verdict", "MONITOR")).upper()
            c = float(d.get("confidence", 0.5))
            r = str(d.get("reason", d.get("reasoning", "")))[:120]
            verdict = Verdict(v) if v in Verdict.__members__ else Verdict.MONITOR
            
            # Fallback if reason is empty
            if not r:
                if verdict == Verdict.ALLOW:
                    r = "clean session, no anomalies detected"
                elif verdict == Verdict.MONITOR:
                    r = "suspicious pattern detected"
                else:
                    r = "malicious pattern detected"
            
            return TrustVerdict(
                verdict    = Verdict.MONITOR if c < 0.5 else verdict,
                confidence = max(0.0, min(1.0, c)),
                reason     = r,
                raw        = raw,
            )
        except Exception:
            pass

    # ── Strategy 2: regex JSON extraction ────────────────────
    for pat in [
        r'\{[^{}]*?"verdict"\s*:\s*"[^"]*"[^{}]*?"confidence"\s*:\s*[\d.]+[^{}]*\}',
        r'\{[^{}]*?"confidence"\s*:\s*[\d.]+[^{}]*?"verdict"\s*:\s*"[^"]*"[^{}]*?\}',
        r'\{.*?"verdict".*?\}',
    ]:
        m = re.search(pat, text, re.DOTALL | re.IGNORECASE)
        if m:
            try:
                d = json.loads(m.group())
                v = str(d.get("verdict", "MONITOR")).upper()
                c = float(d.get("confidence", 0.5))
                r = str(d.get("reason", d.get("reasoning", "")))[:120]
                verdict = Verdict(v) if v in Verdict.__members__ else Verdict.MONITOR
                
                # Fallback if reason is empty
                if not r:
                    if verdict == Verdict.ALLOW:
                        r = "clean session, no anomalies detected"
                    elif verdict == Verdict.MONITOR:
                        r = "suspicious pattern detected"
                    else:
                        r = "malicious pattern detected"
                
                return TrustVerdict(
                    verdict    = Verdict.MONITOR if c < 0.5 else verdict,
                    confidence = max(0.0, min(1.0, c)),
                    reason     = r,
                    raw        = raw,
                )
            except Exception:
                continue

    # ── Strategy 3: keyword 
    upper = text.upper()
    if "DENY"    in upper: return TrustVerdict(Verdict.DENY,    0.70, "malicious pattern detected",    raw=raw)
    if "ALLOW"   in upper: return TrustVerdict(Verdict.ALLOW,   0.70, "clean session, no anomalies detected",   raw=raw)
    if "MONITOR" in upper: return TrustVerdict(Verdict.MONITOR, 0.60, "suspicious pattern detected", raw=raw)

    return TrustVerdict(Verdict.MONITOR, 0.50, "suspicious pattern detected", raw=raw)


class OllamaClient:

    def __init__(
        self,
        endpoint:    str,
        model:       str,
        timeout:     int   = 90,
        temperature: float = 0.1,
        max_tokens:  int   = 300,
    ):
        self.endpoint    = endpoint.rstrip("/")
        self.model       = model
        self.timeout     = timeout
        self.temperature = temperature
        self.max_tokens  = max_tokens
        self._http: Optional[httpx.AsyncClient] = None
        # Simple LRU cache keyed on anomaly fingerprint
        self._cache: dict[str, TrustVerdict] = {}
        self._cache_hits  = 0
        self._cache_misses = 0

    async def _client(self) -> httpx.AsyncClient:
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(
                base_url=self.endpoint,
                timeout=httpx.Timeout(None),   # no timeout
                transport=httpx.AsyncHTTPTransport(retries=0)  # no retries — fail fast and let circuit breaker handle it
            )
        return self._http

    async def ping(self) -> bool:
        try:
            r = await (await self._client()).get("/api/tags")
            return r.status_code == 200
        except Exception:
            return False

    async def list_models(self) -> list[str]:
        try:
            r = await (await self._client()).get("/api/tags")
            return [m["name"] for m in r.json().get("models", [])]
        except Exception:
            return []

    @retry(
        stop=stop_after_attempt(2),
        wait=wait_exponential(min=1, max=6),
        retry=retry_if_exception_type(
            (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError)
        ),
    )
    async def _raw_generate(self, prompt: str) -> str:
        r = await (await self._client()).post(
            "/api/generate",
            json={
                "model":  self.model,
                "prompt": prompt,
                "system": SYSTEM_PROMPT,
                "stream": False,
                "options": {
                    "temperature": self.temperature,
                    "top_p":       0.9,
                    "num_predict": self.max_tokens,
                    "stop":        ["\n\n", "```", "---"],
                },
            },
        )
        r.raise_for_status()
        return r.json().get("response", "").strip()

    def _cache_key(self, session: dict) -> str:
        import hashlib
        import json
        key_data = {
            "entity_id": session.get("entity_id", ""),
            "anomalies": session.get("anomalies", {}),
            "intent":    session.get("intent", ""),
        }
        return hashlib.sha256(
            json.dumps(key_data, sort_keys=True).encode()
        ).hexdigest()

    async def evaluate(self, session: dict) -> TrustVerdict:
        """Evaluate a session — main public API."""
        # Check cache for identical anomaly pattern
        ck = self._cache_key(session)
        if ck in self._cache:
            self._cache_hits += 1
            v = self._cache[ck]
            return TrustVerdict(
                v.verdict, v.confidence, v.reason,
                latency_ms=0.0, from_cache=True
            )
        self._cache_misses += 1

        t0 = time.monotonic()
        try:
            log.info("ollama_evaluating_session", session=session)
            raw     = await self._raw_generate(build_prompt(session))
            verdict = _parse(raw)
            verdict.latency_ms = (time.monotonic() - t0) * 1000

            # Cache all patterns (ALLOW, DENY, MONITOR) so repeated requests from same entity short-circuit
            if len(self._cache) > 500:
                self._cache.pop(next(iter(self._cache)))
            self._cache[ck] = verdict

            log.info(
                "ollama_verdict",
                model      = self.model,
                verdict    = verdict.verdict,
                confidence = verdict.confidence,
                latency_ms = round(verdict.latency_ms, 1),
                entity     = str(session.get("entity_id", ""))[:12],
                cached     = False,
            )
            return verdict

        except Exception as exc:
            ms = (time.monotonic() - t0) * 1000
            log.error("ollama_error", error=str(exc), ms=round(ms, 1))
            return TrustVerdict(
                Verdict.MONITOR, 0.0,
                f"ollama_error:{str(exc)[:60]}",
                latency_ms=ms,
            )

    @property
    def cache_stats(self) -> dict:
        return {"hits": self._cache_hits, "misses": self._cache_misses,
                "size": len(self._cache)}

    async def close(self):
        if self._http and not self._http.is_closed:
            await self._http.aclose()
