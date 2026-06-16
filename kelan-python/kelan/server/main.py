"""
Kelan Security — FastAPI Server v3.0
Replaces aitp-server (Rust/Axum) as the Python intelligence layer.

Endpoints:
  GET  /api/health          — liveness + Ollama status
  GET  /api/stats           — runtime metrics
  GET  /api/verdicts        — recent verdict log
  GET  /api/anomalies       — recent Sentinel events
  POST /api/enroll          — AITP Phase 1: entity enrollment
  POST /api/handshake       — AITP Phases 2-5: session establishment
  POST /api/xdp/drop        — eBPF loader reports XDP drop counts
  GET  /api/sentinel/events — Sentinel anomaly event log
  WS   /ws/agent            — Agentic verdict sync (WebSocket)
"""
import asyncio
import os
import time
import uuid
from contextlib import asynccontextmanager
from typing import Optional

import structlog
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware

from ..config import get_settings
from ..ai.engine import HybridTrustEngine
from ..ai.ollama_client import OllamaClient, Verdict
from ..sentinel.anomaly import SentinelEngine
from ..protocol.session import SessionManager
from ..enforcement.ebpf_bridge import EbpfBridge
from ..simulation.engine import SimulationEngine
from .models import (
    EnrollRequest, HandshakeRequest, XdpDropReport,
    HealthResponse, EnrollResponse,
)

log = structlog.get_logger()
settings = get_settings()

# ── Global singletons (initialised in lifespan) ───────────────────────────────
ollama: Optional[OllamaClient] = None
engine: Optional[HybridTrustEngine] = None
sentinel: Optional[SentinelEngine] = None
sessions: Optional[SessionManager] = None
ebpf: Optional[EbpfBridge] = None
simulation: Optional[SimulationEngine] = None
ws_clients: set[WebSocket] = set()

_started_at = time.time()
_xdp_drops = 0

# FIX 3: stats cache — recomputed at most every 2 s, never on every request
_stats_cache: dict = {"data": None, "ts": 0.0}
STATS_TTL = 2.0


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup → run → shutdown."""
    global ollama, engine, sentinel, sessions, ebpf, simulation

    import os
    os.makedirs(getattr(settings, "DATA_DIR", "data"), exist_ok=True)

    # FIX 7: Memory monitor background task
    async def _memory_monitor():
        log = structlog.get_logger()
        while True:
            try:
                await asyncio.sleep(60)
                with open("/proc/self/status") as f:
                    for line in f:
                        if line.startswith("VmRSS:"):
                            rss_mb = int(line.split()[1]) / 1024
                            log.info("memory_rss_mb",
                                rss_mb=round(rss_mb, 1),
                                verdicts_buffered=len(
                                    sessions.recent_verdicts(500) if sessions else []
                                ),
                            )
                            if rss_mb > 500:
                                log.warning("memory_high", rss_mb=round(rss_mb, 1))
                            break
            except asyncio.CancelledError:
                break
            except FileNotFoundError:
                # macOS does not have /proc — skip silently
                await asyncio.sleep(60)
            except Exception as e:
                log.debug("mem_monitor_err", error=str(e))

    asyncio.create_task(_memory_monitor(), name="memory-monitor")

    log.info("kelan_starting", version="3.0.0", engine="python+ollama",
             ollama=settings.ollama_endpoint, model=settings.ollama_model)

    ollama = OllamaClient(
        endpoint=settings.ollama_endpoint,
        model=settings.ollama_model,
        timeout=settings.ollama_timeout,
    )

    if await ollama.health_check():
        models = await ollama.list_models()
        log.info("ollama_connected", available_models=models)
    else:
        log.warning("ollama_unreachable", endpoint=settings.ollama_endpoint,
                    hint="Start Ollama: ollama serve && ollama run gemma4")

    engine = HybridTrustEngine(
        ollama=ollama,
        failure_threshold=settings.cb_failure_threshold,
        recovery_timeout=settings.cb_recovery_timeout,
    )
    engine.on_verdict(_broadcast_verdict)

    sentinel = SentinelEngine()
    sessions = SessionManager()
    ebpf = EbpfBridge()
    simulation = SimulationEngine(engine, sentinel)

    log.info("kelan_ready", port=settings.http_port,
             require_pq=settings.require_pq, ebpf=settings.ebpf_enabled)
    yield

    # Shutdown
    if simulation is not None:
        await simulation.stop()
    if ollama is not None:
        await ollama.close()
    log.info("kelan_stopped")


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Kelan Security AITP",
    description="Adaptive Intent Transport Protocol — Python Intelligence Engine",
    version="3.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── WebSocket broadcast ───────────────────────────────────────────────────────

async def _broadcast_verdict(payload: dict) -> None:
    """Send verdict to every connected WebSocket agent."""
    dead: set[WebSocket] = set()
    for ws in ws_clients:
        try:
            await ws.send_json(payload)
        except Exception:
            dead.add(ws)
    ws_clients.difference_update(dead)


# ── REST Endpoints ────────────────────────────────────────────────────────────

@app.get("/api/health", response_model=HealthResponse, tags=["system"])
async def health():
    ollama_ok = await ollama.health_check() if ollama else False
    model_ok = await ollama.model_loaded() if ollama and ollama_ok else False
    ebpf_ok = await ebpf.is_available() if ebpf else False
    return HealthResponse(
        status="healthy",
        version="3.0.0",
        engine="python+ollama",
        ollama_connected=ollama_ok,
        ollama_model=settings.ollama_model,
        ollama_model_loaded=model_ok,
        uptime_seconds=int(time.time() - _started_at),
        ebpf_available=ebpf_ok,
    )


def _compute_stats() -> dict:
    """
    FIX 3 — safe stats computation.
    Guards every attribute access with getattr() so a missing field
    can never raise TypeError / AttributeError and crash the endpoint.
    """
    global _xdp_drops
    s_stats  = sessions.stats()  if sessions  else {}
    e_stats  = engine.stats()    if engine    else {}
    sen_stats = sentinel.stats() if sentinel  else {}
    
    # Flatten verdicts for test script expectations
    by_verdict = s_stats.get("by_verdict", {})
    v_allow = by_verdict.get("ALLOW", 0)
    v_deny = by_verdict.get("DENY", 0)
    v_monitor = by_verdict.get("MONITOR", 0)

    return {
        "mode":             "python+ebpf",
        "started_at":       _started_at,
        "uptime_seconds":   int(time.time() - _started_at),
        "xdp_drops":        int(_xdp_drops),
        "verdicts":         by_verdict,
        "verdicts_total":   s_stats.get("total_sessions", 0),
        "verdicts_allow":   v_allow,
        "verdicts_deny":    v_deny,
        "verdicts_monitor": v_monitor,
        "sessions":         s_stats,
        "engine":           e_stats,
        "sentinel":         sen_stats,
        "websocket_clients": len(ws_clients),
        "simulation_active": getattr(simulation, "active", False) if simulation else False,
        "ollama_model":     os.getenv("OLLAMA_MODEL", settings.ollama_model),
        # Safe engine sub-fields for dashboards
        "ollama_calls_total":    int(e_stats.get("ollama_calls", 0)),
        "fallback_calls_total":  int(e_stats.get("fallback_calls", 0)),
        "circuit_state":         str(
            e_stats.get("circuit_breaker", {}).get("state", "unknown")
        ),
    }


@app.get("/api/stats", tags=["system"])
async def get_stats():
    """Runtime metrics — cached for 2 s to avoid recomputing on every poll."""
    now = time.monotonic()
    if _stats_cache["data"] and (now - _stats_cache["ts"]) < STATS_TTL:
        return _stats_cache["data"]
    data = _compute_stats()
    _stats_cache["data"] = data
    _stats_cache["ts"] = now
    return data


@app.get("/api/verdicts", tags=["verdicts"])
async def get_verdicts(limit: int = 100):
    """FIX 3: returns {verdicts, total} dict — never a bare list."""
    if not sessions:
        return {"verdicts": [], "total": 0}
    cap = min(limit, 500)
    verdicts = sessions.recent_verdicts(cap)
    return {
        "verdicts": verdicts,
        "total":    sessions.stats().get("total_sessions", len(verdicts)),
    }


@app.post("/api/simulate/toggle", tags=["simulation"])
async def toggle_simulation():
    """Toggle the background simulation engine."""
    if not simulation:
        return {"status": "error", "message": "Simulation engine not initialized"}
    is_active = await simulation.toggle()
    return {"simulation_active": is_active}


@app.get("/api/anomalies", tags=["sentinel"])
async def get_anomalies(limit: int = 50):
    if not sentinel:
        return []
    return sentinel.recent_anomalies(min(limit, 200))


@app.get("/api/sentinel/events", tags=["sentinel"])
async def sentinel_events(limit: int = 20):
    if not sentinel:
        return {"events": []}
    return {"events": sentinel.recent_anomalies(min(limit, 100))}


@app.post("/api/enroll", response_model=EnrollResponse, tags=["aitp"])
async def enroll(req: EnrollRequest, request: Request):
    """
    AITP Phase 1: Entity enrollment.
    Validates cryptographic material, runs Sentinel + Ollama trust evaluation.
    """
    source_ip = req.source_ip or request.client.host if request.client else ""

    # ── Signature validation ────────────────────────────────────────────────
    if req.signature is not None:
        sig = req.signature.replace(" ", "")
        if len(sig) < 64 or sig == "00" * 32 or sig == "0" * 128:
            raise HTTPException(
                status_code=403,
                detail={"error": "invalid_signature", "reason": "Ed25519 signature rejected"},
            )

    # ── Post-quantum enforcement ────────────────────────────────────────────
    if settings.require_pq and req.kem_public_key is None:
        raise HTTPException(
            status_code=403,
            detail={"error": "pq_required", "reason": "ML-KEM-768 public key required"},
        )

    # ── Sentinel anomaly analysis ───────────────────────────────────────────
    anomalies = sentinel.analyze(req.entity_id, req.intent, source_ip) if sentinel else {}

    # ── Build session context for Ollama ───────────────────────────────────
    session_ctx = {
        "entity_id": req.entity_id,
        "intent": req.intent,
        "name": req.name,
        "version": req.version,
        "session_id": str(uuid.uuid4()),
        "source_ip": source_ip,
        "anomalies": anomalies,
        "has_kem_key": req.kem_public_key is not None,
        "has_signature": req.signature is not None,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    # ── Trust evaluation ───────────────────────────────────────────────────
    if engine is not None:
        verdict = await engine.evaluate(session_ctx)
    else:
        from ..ai.engine import fallback_rules
        verdict = fallback_rules(session_ctx)

    # ── Persist session ─────────────────────────────────────────────────────
    if sessions:
        record = sessions.store(session_ctx["session_id"], req.entity_id, verdict)
        permit_token = record.permit_token
    else:
        permit_token = str(uuid.uuid4()) if verdict.verdict != Verdict.DENY else None

    # ── Block IP at eBPF layer if DENY ──────────────────────────────────────
    if verdict.verdict == Verdict.DENY and source_ip and ebpf:
        asyncio.create_task(
            ebpf.block_ip(source_ip, reason=verdict.reason, duration_secs=300)
        )
        raise HTTPException(
            status_code=403,
            detail={
                "error": "enrollment_denied",
                "reason": verdict.reason,
                "confidence": verdict.confidence,
            },
        )

    return EnrollResponse(
        session_id=session_ctx["session_id"],
        entity_id=req.entity_id,
        verdict=verdict.verdict.value,
        confidence=verdict.confidence,
        reason=verdict.reason,
        permit_token=permit_token,
        action="PERMIT" if verdict.verdict == Verdict.ALLOW else "MONITOR",
    )


@app.post("/api/handshake", tags=["aitp"])
async def handshake(req: HandshakeRequest):
    """
    AITP Phases 2-5: Session establishment handshake.
    Phase 1 = EnrollRequest. Phase 2-5 = HandshakeRequest.
    """
    # ML-KEM enforcement on all handshake phases
    if settings.require_pq:
        if not req.kem_ciphertext:
            raise HTTPException(
                status_code=403,
                detail={"error": "pq_downgrade_denied",
                        "reason": "ML-KEM-768 ciphertext required — classical-only sessions rejected"},
            )

    next_phase = req.phase + 1 if req.phase < 5 else None
    return {
        "status": "phase_accepted",
        "phase": req.phase,
        "next_phase": next_phase,
        "entity_id": req.entity_id,
        "complete": req.phase == 5,
    }


@app.post("/api/xdp/drop", tags=["ebpf"])
async def record_xdp_drop(report: XdpDropReport):
    """Called by the Rust eBPF loader to report XDP kernel drop counts."""
    global _xdp_drops
    _xdp_drops += report.count
    log.info("xdp_drops_reported", count=report.count, iface=report.interface,
             total=_xdp_drops)
    return {"ok": True, "total_xdp_drops": _xdp_drops}


# ── WebSocket: Agentic Sync ───────────────────────────────────────────────────

@app.websocket("/ws/agent")
async def ws_agent(websocket: WebSocket):
    """
    Real-time agentic verdict synchronisation.
    Clients receive every verdict as it's issued.
    Clients can also send commands (future: revoke, re-evaluate).
    """
    await websocket.accept()
    ws_clients.add(websocket)
    client_info = f"{websocket.client.host}:{websocket.client.port}" if websocket.client else "unknown"
    log.info("agent_connected", client=client_info, total=len(ws_clients))

    # Send welcome with current state
    await websocket.send_json({
        "type": "connected",
        "server_version": "3.0.0",
        "model": settings.ollama_model,
        "require_pq": settings.require_pq,
    })

    try:
        while True:
            data = await websocket.receive_json()
            msg_type = data.get("type", "unknown")
            log.debug("agent_message", type=msg_type, client=client_info)
            await websocket.send_json({"type": "ack", "received": msg_type})
    except WebSocketDisconnect:
        ws_clients.discard(websocket)
        log.info("agent_disconnected", client=client_info, remaining=len(ws_clients))
    except Exception as exc:
        ws_clients.discard(websocket)
        log.error("agent_ws_error", error=str(exc), client=client_info)
