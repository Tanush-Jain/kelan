"""
Ollama Client — Local LLM inference via HTTP.
Connects to Ollama running locally or on the MacBook (OLLAMA_ENDPOINT).
NO external API calls. NO API keys. NO cloud dependencies.

 FIX 1 — Session leak:
   ONE shared httpx.AsyncClient per OllamaClient instance.
   Created lazily inside an asyncio.Lock → no per-request client creation.
   Closed explicitly on shutdown via close().

 Model switching:
   Set OLLAMA_MODEL in .env — _get_model_options() auto-adjusts
   generation params (temperature, num_predict, stop tokens) per model.
"""
import asyncio
import json
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import httpx
import structlog
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from .prompts import build_evaluation_prompt, VERIFY_PROMPT

log = structlog.get_logger()


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    MONITOR = "MONITOR"


@dataclass
class TrustVerdict:
    verdict: Verdict
    confidence: float
    reason: str
    raw_response: str = field(default="", repr=False)

    @property
    def is_decisive(self) -> bool:
        return self.confidence >= 0.5

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "confidence": round(self.confidence, 4),
            "reason": self.reason,
        }


class OllamaClient:
    """
    Async HTTP client for local Ollama inference.
    Handles retries, connection pooling, and verdict JSON parsing.

    FIX 1 — ONE shared httpx.AsyncClient for the lifetime of this object.
    _session_lock prevents concurrent coroutines from racing to create
    duplicate clients (which would leak connections under high load).
    """

    # ─────────────────────────────────────────────────────────────────────
    # MODEL PRESETS — change OLLAMA_MODEL in .env to switch
    # PRESET_CPU   = "qwen2.5:3b"   # current ✅  (CPU, ~2GB RAM)
    # PRESET_GPU_S = "gemma3:9b"    # future  (6GB VRAM)
    # PRESET_GPU_L = "gemma3:27b"   # future  (18GB VRAM)
    # PRESET_ALT   = "mistral:7b"   # future  (5GB VRAM)
    # ─────────────────────────────────────────────────────────────────────

    def __init__(self, endpoint: str, model: str, timeout: int = 60):
        self.endpoint = endpoint.rstrip("/")
        # Model resolved from arg → env → default
        # Change OLLAMA_MODEL in .env to switch models without code changes
        self.model = model or os.getenv("OLLAMA_MODEL", "qwen2.5:3b")
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None
        # FIX 1: lock prevents concurrent coroutines racing on _client init
        self._session_lock = asyncio.Lock()

        log.info(
            "ollama_client_init",
            model=self.model,
            endpoint=self.endpoint,
            timeout=self.timeout,
        )

    async def _get_client(self) -> httpx.AsyncClient:
        """Return the shared httpx.AsyncClient, creating it if needed.

        FIX 1: asyncio.Lock ensures only ONE client is created even when
        many coroutines call _get_client() simultaneously at startup.
        """
        async with self._session_lock:
            if self._client is None or self._client.is_closed:
                self._client = httpx.AsyncClient(
                    base_url=self.endpoint,
                    timeout=httpx.Timeout(
                        connect=5.0,
                        read=self.timeout,
                        write=10.0,
                        pool=5.0,
                    ),
                    limits=httpx.Limits(
                        max_connections=20,
                        max_keepalive_connections=10,
                        keepalive_expiry=30.0,
                    ),
                )
                log.debug("ollama_client_created", model=self.model)
        return self._client

    def _get_model_options(self) -> dict:
        """Return Ollama generation options tuned per model size.

        Change OLLAMA_MODEL in .env — this auto-adjusts.
        qwen2.5:3b  → tight stop tokens for clean JSON output on CPU
        gemma3:9b   → more headroom, different stop tokens (future GPU)
        """
        model = self.model.lower()

        # ── qwen2.5:3b (current — CPU, 8 GB RAM) ───────────────────────
        if "qwen" in model or "3b" in model:
            return {
                "temperature": 0.1,
                "top_p": 0.9,
                "num_predict": 80,
                "stop": ["<|im_end|>", "\n\n", "```"],
            }

        # ── gemma3:9b (future GPU — uncomment when ready) ───────────────
        # if "gemma3" in model and "9b" in model:
        #     return {
        #         "temperature": 0.15,
        #         "top_p":       0.95,
        #         "num_predict": 120,
        #         "stop": ["\n\n\n"],
        #     }

        # ── gemma3:27b (future high-end GPU) ────────────────────────────
        # if "gemma3" in model and "27b" in model:
        #     return {
        #         "temperature": 0.1,
        #         "top_p":       0.95,
        #         "num_predict": 150,
        #         "stop": ["\n\n\n"],
        #     }

        # ── mistral:7b (alternative GPU) ────────────────────────────────
        # if "mistral" in model:
        #     return {
        #         "temperature": 0.1,
        #         "top_p":       0.9,
        #         "num_predict": 100,
        #         "stop": ["</s>", "\n\n"],
        #     }

        # ── fallback defaults ────────────────────────────────────────────
        return {
            "temperature": 0.1,
            "num_predict": 80,
        }

    async def health_check(self) -> bool:
        """Returns True if Ollama is reachable."""
        try:
            client = await self._get_client()
            resp = await client.get("/api/tags", timeout=5)
            return resp.status_code == 200
        except Exception:
            return False

    async def list_models(self) -> list[str]:
        """Return list of available model names."""
        try:
            client = await self._get_client()
            resp = await client.get("/api/tags", timeout=10)
            data = resp.json()
            return [m["name"] for m in data.get("models", [])]
        except Exception:
            return []

    async def model_loaded(self) -> bool:
        """Check if the configured model is available."""
        models = await self.list_models()
        return any(m.startswith(self.model.split(":")[0]) for m in models)

    @retry(
        stop=stop_after_attempt(2),
        wait=wait_exponential(multiplier=1, min=1, max=5),
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.ConnectError)),
        reraise=True,
    )
    async def _generate(self, prompt: str) -> str:
        """Raw generation call — retried on transient network errors.

        Uses the shared client (FIX 1) and model-aware options.
        To switch models: change OLLAMA_MODEL in .env, restart server.
        """
        # FIX 1: reuses the shared client — no per-request client creation
        client = await self._get_client()
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            # Options auto-tuned per model via _get_model_options()
            "options": self._get_model_options(),
        }
        resp = await client.post("/api/generate", json=payload)
        resp.raise_for_status()
        return resp.json().get("response", "").strip()

    def _parse_verdict(self, raw: str) -> TrustVerdict:
        """
        Parse Ollama response into a structured TrustVerdict.
        Tries multiple strategies: direct JSON, JSON extraction, keyword fallback.
        """
        # Strategy 1: direct JSON
        try:
            d = json.loads(raw)
            return self._build_verdict(d, raw)
        except (json.JSONDecodeError, ValueError):
            pass

        # Strategy 2: find JSON block in freetext
        patterns = [
            r'\{[^{}]*?"verdict"\s*:\s*"[^"]*"[^{}]*?\}',
            r'\{.*?"verdict".*?\}',
        ]
        for pattern in patterns:
            m = re.search(pattern, raw, re.DOTALL)
            if m:
                try:
                    d = json.loads(m.group())
                    return self._build_verdict(d, raw)
                except Exception:
                    continue

        # Strategy 3: keyword detection (last resort)
        upper = raw.upper()
        if "DENY" in upper:
            return TrustVerdict(Verdict.DENY, 0.65, "keyword-detected:DENY", raw)
        if "ALLOW" in upper:
            return TrustVerdict(Verdict.ALLOW, 0.65, "keyword-detected:ALLOW", raw)
        return TrustVerdict(Verdict.MONITOR, 0.5, "unparseable-response", raw)

    @staticmethod
    def _build_verdict(d: dict, raw: str) -> TrustVerdict:
        verdict_str = str(d.get("verdict", "MONITOR")).upper()
        confidence = float(d.get("confidence", 0.5))
        reason = str(d.get("reason", "no-reason"))[:100]
        try:
            verdict = Verdict(verdict_str)
        except ValueError:
            verdict = Verdict.MONITOR
        # Enforce low-confidence override
        if confidence < 0.5:
            verdict = Verdict.MONITOR
        return TrustVerdict(verdict, confidence, reason, raw)

    async def evaluate_session(self, session: dict) -> TrustVerdict:
        """Main entry — evaluate a network session and return a verdict."""
        prompt = build_evaluation_prompt(session)
        try:
            raw = await self._generate(prompt)
            verdict = self._parse_verdict(raw)
            log.info(
                "ollama_verdict",
                model=self.model,
                entity=session.get("entity_id"),
                verdict=verdict.verdict.value,
                confidence=verdict.confidence,
                reason=verdict.reason,
            )
            return verdict
        except Exception as exc:
            log.error("ollama_error", error=str(exc), entity=session.get("entity_id"))
            raise

    async def verify_role(self) -> bool:
        """Quick check that the model understands its security role."""
        try:
            raw = await self._generate(VERIFY_PROMPT)
            d = json.loads(raw)
            return d.get("status") == "ok"
        except Exception:
            return False

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
