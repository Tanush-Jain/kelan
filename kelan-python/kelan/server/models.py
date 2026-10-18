"""
Pydantic request/response models for the Kelan Security FastAPI server.
"""
from typing import Optional
from pydantic import BaseModel, Field


# ── Requests ─────────────────────────────────────────────────────────────────

class EnrollRequest(BaseModel):
    entity_id: str = Field(..., description="Unique entity identifier")
    intent: str = Field(default="INIT_ENROL", description="AITP intent verb")
    name: str = Field(default="", description="Human-readable entity name")
    version: int = Field(default=1, description="Protocol version")
    # Cryptographic material (optional during testing)
    x25519_public_key: Optional[str] = Field(default=None, description="X25519 DH public key (hex)")
    kem_public_key: Optional[str] = Field(default=None, description="ML-KEM-768 public key (hex)")
    signature: Optional[str] = Field(default=None, description="Ed25519 signature (hex)")
    nonce: Optional[str] = Field(default=None, description="Random nonce (hex)")
    source_ip: Optional[str] = Field(default=None, description="Reported source IP")

    model_config = {"json_schema_extra": {"example": {
        "entity_id": "prod-api-server-01",
        "intent": "INIT_ENROL",
        "name": "Production API",
        "version": 1,
    }}}


class HandshakeRequest(BaseModel):
    entity_id: str
    phase: int = Field(..., ge=1, le=5, description="AITP handshake phase (1-5)")
    intent: str = Field(default="INIT_SESSION")
    x25519_public_key: Optional[str] = None
    kem_ciphertext: Optional[str] = None
    signature: Optional[str] = None
    session_token: Optional[str] = None


class XdpDropReport(BaseModel):
    count: int = Field(default=1, ge=1)
    interface: str = Field(default="")


# ── Responses ─────────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str
    version: str
    engine: str
    ollama_connected: bool
    ollama_model: str
    ollama_model_loaded: bool
    uptime_seconds: int
    ebpf_available: bool


class EnrollResponse(BaseModel):
    session_id: str
    entity_id: str
    verdict: str
    confidence: float
    reason: str
    permit_token: Optional[str]
    action: str


class StatsResponse(BaseModel):
    mode: str
    started_at: float
    uptime_seconds: int
    verdicts: dict
    sessions: dict
    engine: dict
    sentinel: dict
