"""
Kelan Security — FastAPI Server
Full replacement for Rust aitp-server.
Endpoints: health, stats, verdicts, anomalies,
           enroll, handshake, xdp/drop, /ws/agent
"""
import time
import uuid
import asyncio
import os
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Optional, Any, cast

import structlog
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST, REGISTRY
from starlette.responses import Response
# pyrefly: ignore [missing-import]
from pydantic import BaseModel

from ..config import get_settings
from ..ai.ollama_client import OllamaClient, Verdict
from ..ai.engine import HybridTrustEngine
from ..sentinel.detector import SentinelDetector
from ..enforcement.ebpf_bridge import EbpfBridge
from ..protocol.handshake import HandshakeManager, HandshakeError
from ..db.database import init_db, save_verdict, fetch_verdicts, fetch_anomalies, get_session
from ..db.models import Entity, Session

log = structlog.get_logger()
cfg = get_settings()

# ── Prometheus metrics 
if "kelan_requests_total" in REGISTRY._names_to_collectors:
    REQ_COUNT = cast(Counter, REGISTRY._names_to_collectors["kelan_requests_total"])
else:
    REQ_COUNT = Counter("kelan_requests_total", "Total requests", ["endpoint"])

if "kelan_api_verdicts_total" in REGISTRY._names_to_collectors:
    VERDICT_COUNT = cast(Counter, REGISTRY._names_to_collectors["kelan_api_verdicts_total"])
else:
    VERDICT_COUNT = Counter("kelan_api_verdicts_total", "Verdicts", ["verdict"])

if "kelan_ollama_latency_ms" in REGISTRY._names_to_collectors:
    OLLAMA_LAT = cast(Histogram, REGISTRY._names_to_collectors["kelan_ollama_latency_ms"])
else:
    OLLAMA_LAT = Histogram("kelan_ollama_latency_ms", "Ollama latency ms",
                           buckets=[50, 100, 200, 500, 1000, 2000, 5000])

# ── Global singletons 
ollama:    Optional[OllamaClient]     = None
engine:    Optional[HybridTrustEngine] = None
sentinel:  Optional[SentinelDetector] = None
ebpf:      Optional[EbpfBridge]       = None
handshake_mgr: Optional[HandshakeManager] = None

_ws_clients: set[WebSocket] = set()
_start_time = time.time()
_xdp_drops = 0

# In-memory ring buffers
_verdict_buf: list[dict] = []
_MAX_BUF = 1000


# ── Application lifespan 
@asynccontextmanager
async def lifespan(app: FastAPI):
    global ollama, engine, sentinel, ebpf, handshake_mgr

    log.info("kelan_starting", port=cfg.http_port, model=cfg.ollama_model)

    await init_db()

    ollama   = OllamaClient(cfg.ollama_endpoint, cfg.ollama_model,
                            cfg.ollama_timeout, cfg.ollama_temperature)
    sentinel = SentinelDetector()
    ebpf     = EbpfBridge()
    handshake_mgr = HandshakeManager(require_pq=cfg.require_pq)

    engine = HybridTrustEngine(ollama, cfg.cb_threshold, cfg.cb_recovery)
    engine.on_verdict(_on_verdict)

    await ebpf.start()

    ok = await ollama.ping()
    log.info("ollama_status", connected=ok, model=cfg.ollama_model,
             endpoint=cfg.ollama_endpoint)
    if ok:
        models = await ollama.list_models()
        log.info("models_available", models=models)
    else:
        log.warning("ollama_unreachable",
                    fix="run: ollama serve  (on macOS/Linux)")
    yield

    await ebpf.stop()
    await ollama.close()
    log.info("kelan_stopped")


# ── App 
app = FastAPI(
    title="Kelan Security Intelligence",
    version="4.0.0-python",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                  allow_methods=["*"], allow_headers=["*"])

from prometheus_fastapi_instrumentator import Instrumentator
Instrumentator().instrument(app).expose(app)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


# ── Helpers 
async def _on_verdict(payload: dict):
    """Called on every verdict — store + broadcast."""
    _verdict_buf.append(payload)
    if len(_verdict_buf) > _MAX_BUF:
        _verdict_buf.pop(0)
    # Persist to DB
    await save_verdict(
        payload.get("session_id", ""),
        payload.get("entity_id", ""),
        payload.get("verdict", ""),
        payload.get("confidence", 0.0),
        payload.get("reason", ""),
        payload.get("latency_ms", 0.0),
        payload.get("anomalies", {}),
    )
    # eBPF enforcement
    if ebpf:
        if payload.get("action") == "REVOKE":
            await ebpf.revoke(payload.get("entity_id", ""))
        elif payload.get("action") == "PERMIT":
            await ebpf.permit(
                payload.get("session_id", ""),
                payload.get("entity_id", ""),
            )
    # WebSocket broadcast
    dead = set()
    for ws in _ws_clients:
        try:
            await ws.send_json(payload)
        except Exception:
            dead.add(ws)
    _ws_clients.difference_update(dead)


import hmac
import hashlib
import base64
import json
from collections import defaultdict
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Depends

# In-memory store for registered organisations
_organisations: dict[str, dict] = {}
_rate_limit_history = defaultdict(list)

# Password hashing
def hash_password(password: str) -> str:
    salt = b"kelan_security_salt_12345"
    iterations = 100000
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return dk.hex()

def verify_password_hash(password: str, password_hash: str) -> bool:
    return hmac.compare_digest(hash_password(password), password_hash)

# JWT helpers
def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def base64url_decode(data: str) -> bytes:
    padding = '=' * (4 - len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)

def encode_jwt(claims: dict, secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = base64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
    payload_b64 = base64url_encode(json.dumps(claims, separators=(',', ':')).encode('utf-8'))
    signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
    signature = hmac.new(secret.encode('utf-8'), signing_input, hashlib.sha256).digest()
    signature_b64 = base64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{signature_b64}"

def decode_jwt(token: str, secret: str) -> dict:
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid token format")
    header_b64, payload_b64, signature_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
    expected_signature = hmac.new(secret.encode('utf-8'), signing_input, hashlib.sha256).digest()
    expected_signature_b64 = base64url_encode(expected_signature)
    if not hmac.compare_digest(signature_b64.encode('utf-8'), expected_signature_b64.encode('utf-8')):
        raise ValueError("Invalid signature")
    payload = json.loads(base64url_decode(payload_b64).decode('utf-8'))
    exp = payload.get("exp")
    if exp and time.time() > exp:
        raise ValueError("Token expired")
    return payload

security = HTTPBearer(auto_error=False)

async def get_current_org(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Missing authorization header")
    token = credentials.credentials
    try:
        claims = decode_jwt(token, cfg.jwt_secret)
        return claims
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid or expired token: {e}")

def enforce_rate_limit(request: Request, limit: int = 50, window: int = 60):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    timestamps = [t for t in _rate_limit_history[client_ip] if now - t < window]
    _rate_limit_history[client_ip] = timestamps
    
    if len(timestamps) >= limit:
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please try again later."
        )
    _rate_limit_history[client_ip].append(now)

# ── Request Models 
class SignupReq(BaseModel):
    org_name: str
    email: Optional[str] = None
    password: Optional[str] = None
    entity_id: Optional[str] = None
    tier: Optional[str] = None

class SigninReq(BaseModel):
    email: str
    password: str

class CreateEntityReq(BaseModel):
    name: str
    entity_type: str
    department: Optional[str] = None
    clearance_level: Optional[int] = None
    allowed_intents: Optional[list[str]] = None

class TestSessionReq(BaseModel):
    dest_entity_id: str
    intent: str
    bytes_tx: Optional[int] = 0
    simulate_lateral_movement: Optional[bool] = False

class VerifyKeyReq(BaseModel):
    provider: str
    model: str
    api_key: str

class EnrollReq(BaseModel):
    entity_id:          str
    intent:             str   = "INIT_ENROL"
    name:               str   = ""
    version:            Any   = 1
    x25519_public_key:  Optional[str] = None
    kem_public_key:     Optional[str] = None
    signature:          Optional[str] = None
    nonce:              Optional[str] = None
    metadata:           Optional[dict] = None


class HandshakeReq(BaseModel):
    session_id:        Optional[str] = None
    entity_id:         str
    phase:             int   = 1
    intent:            str   = "INIT_SESSION"
    nonce_c:           Optional[str] = None
    x25519_public_key: Optional[str] = None
    kem_ciphertext:    Optional[str] = None
    kem_public_key:    Optional[str] = None
    signature:         Optional[str] = None
    ed25519_public_key: Optional[str] = None


class TrustEvalReq(BaseModel):
    entity_id:  str
    intent:     str
    session_id: str
    anomalies:  Optional[Any] = None


class XdpDropReport(BaseModel):
    count:     int
    interface: str = "eth0"
    reason:    Optional[str] = None


# ── Routes

@app.get("/")
@app.get("/dashboard")
async def get_dashboard():
    return FileResponse("static/index.html")


@app.get("/terminal")
@app.get("/logs/terminal.html")
@app.get("/log/terminal.html")
async def get_terminal_dashboard():
    if os.path.exists("log/terminal.html"):
        return FileResponse("log/terminal.html")
    return FileResponse("static/index.html")


@app.get("/health")
@app.get("/api/health")
async def health():
    REQ_COUNT.labels("health").inc()
    ok = await ollama.ping() if ollama else False
    return {
        "status":           "healthy",
        "legacy_status":    "ok",
        "version":          "4.0.0-python",
        "engine":           "fastapi+ollama",
        "ollama_connected": ok,
        "ollama_model":     cfg.ollama_model,
        "ebpf_mode":        ebpf.mode if ebpf else "unknown",
        "uptime_s":         int(time.time() - _start_time),
    }


@app.get("/api/stats")
async def stats():
    REQ_COUNT.labels("stats").inc()
    eng = engine.stats if engine else {}
    return {
        "requests":         eng.get("total", 0),
        "verdicts_total":   eng.get("total", 0),
        "allow":            eng.get("allow", 0),
        "deny":             eng.get("deny", 0),
        "monitor":          eng.get("monitor", 0),
        "fallbacks":        eng.get("fallbacks", 0),
        "circuit_state":    eng.get("circuit", "unknown"),
        "cache":            eng.get("cache", {}),
        "ebpf_mode":        ebpf.mode if ebpf else "unknown",
        "packets_dropped":  _xdp_drops,
        "ollama_model":     cfg.ollama_model,
        "uptime_s":         int(time.time() - _start_time),
        "ai_calls":         eng.get("total", 0),
        "blocked_today":    eng.get("deny", 0),
    }


@app.get("/api/verdicts")
async def verdicts(limit: int = 100):
    REQ_COUNT.labels("verdicts").inc()
    return {"verdicts": await fetch_verdicts(limit=limit)}


@app.get("/api/anomalies")
@app.get("/api/sentinel/anomalies")
async def anomalies(limit: int = 50):
    REQ_COUNT.labels("anomalies").inc()
    return {"anomalies": await fetch_anomalies(limit=limit)}


@app.get("/api/sentinel/events")
async def sentinel_events(limit: int = 20):
    REQ_COUNT.labels("sentinel_events").inc()
    events = sentinel.recent(n=limit) if sentinel else []
    return {"events": events}


@app.post("/api/enroll")
async def enroll(req: EnrollReq, request: Request):
    REQ_COUNT.labels("enroll").inc()
    
    # signature validation
    if req.signature is not None:
        from ..protocol.crypto import is_valid_ed25519_sig
        if not is_valid_ed25519_sig(req.signature):
            raise HTTPException(
                status_code=403,
                detail={"error": "invalid_signature", "reason": "Ed25519 signature rejected"},
            )
            
    # post-quantum enforcement
    if cfg.require_pq:
        if not req.kem_public_key or len(req.kem_public_key) != 2368:
            raise HTTPException(
                status_code=403,
                detail={"error": "pq_downgrade_denied", "reason": "Post-quantum key exchange required"},
            )
        
    source_ip = request.client.host if request.client else ""
    
    # Sentinel analysis
    anomalies = sentinel.analyze(req.entity_id, req.intent, source_ip) if sentinel else {}
    
    session_id = str(uuid.uuid4())
    session_ctx = {
        "session_id": session_id,
        "entity_id": req.entity_id,
        "intent": req.intent,
        "source_ip": source_ip,
        "anomalies": anomalies,
        "name": req.name,
        "version": req.version,
        "has_kem_key": req.kem_public_key is not None,
        "has_signature": req.signature is not None,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    
    if not engine:
        raise HTTPException(status_code=503, detail="Engine not initialized")
    verdict = await engine.evaluate(session_ctx)
    VERDICT_COUNT.labels(verdict.verdict.value).inc()
    
    if verdict.verdict == Verdict.DENY:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "enrollment_denied",
                "reason": verdict.reason,
                "confidence": verdict.confidence,
            },
        )
        
    permit_token = str(uuid.uuid4())
    
    return {
        "session_id": session_id,
        "entity_id": req.entity_id,
        "verdict": verdict.verdict.value,
        "confidence": verdict.confidence,
        "reason": verdict.reason,
        "permit_token": permit_token,
        "action": "PERMIT" if verdict.verdict == Verdict.ALLOW else "MONITOR",
    }


@app.post("/api/handshake")
async def handshake(req: HandshakeReq, request: Request):
    REQ_COUNT.labels("handshake").inc()
    
    if not handshake_mgr:
        raise HTTPException(status_code=503, detail="Handshake manager not initialized")
        
    # Enforce PQ checks
    if cfg.require_pq:
        if req.phase == 1:
            if not req.kem_public_key or len(req.kem_public_key) != 2368:
                raise HTTPException(
                    status_code=403,
                    detail={"error": "pq_downgrade_denied", "reason": "Post-quantum key exchange required"},
                )
        else:
            if not req.kem_ciphertext or len(req.kem_ciphertext) != 2176:
                raise HTTPException(
                    status_code=403,
                    detail={"error": "pq_downgrade_denied", "reason": "Post-quantum key exchange required"},
                )
        
    try:
        if req.phase == 1:
            nonce_c = req.nonce_c or uuid.uuid4().hex
            source_ip = request.client.host if request.client else ""
            anomalies = sentinel.analyze(req.entity_id, req.intent, source_ip) if sentinel else {}
            if anomalies:
                from ..db.database import save_anomaly
                await save_anomaly(req.entity_id, "handshake_anomaly", 0.7, anomalies)
            
            ps = handshake_mgr.receive_syn(
                entity_id=req.entity_id,
                intent=req.intent,
                nonce_c=nonce_c,
                x25519_pk_c_hex=req.x25519_public_key,
                kem_pk_c_hex=req.kem_public_key,
            )
            
            return {
                "session_id": ps.session_id,
                "phase": 2,
                "kem_ciphertext": ps.kem_ct_s.hex() if ps.kem_ct_s else None,
                "x25519_public_key": ps.x25519_pk_s.hex(),
            }
            
        elif req.phase == 3:
            if not req.session_id:
                raise HTTPException(status_code=400, detail="session_id required for Phase 3")
            if not req.kem_ciphertext or not req.signature or not req.ed25519_public_key:
                raise HTTPException(status_code=400, detail="kem_ciphertext, signature, and ed25519_public_key required for Phase 3")
                
            ps = handshake_mgr.receive_kem_complete(
                session_id=req.session_id,
                kem_ct_c_hex=req.kem_ciphertext,
                signature_hex=req.signature,
                ed25519_pk_hex=req.ed25519_public_key,
            )
            
            source_ip = request.client.host if request.client else ""
            anomalies = sentinel.analyze(ps.entity_id, ps.intent, source_ip) if sentinel else {}
            
            session_ctx = {
                "session_id": ps.session_id,
                "entity_id": ps.entity_id,
                "intent": ps.intent,
                "source_ip": source_ip,
                "anomalies": anomalies,
                "created_at": ps.created_at,
                "pq_enabled": True,
            }
            
            if not engine:
                raise HTTPException(status_code=503, detail="Engine not initialized")
            verdict = await engine.evaluate(session_ctx)
            VERDICT_COUNT.labels(verdict.verdict.value).inc()
            
            if verdict.verdict == Verdict.DENY:
                if source_ip and ebpf:
                    await ebpf.revoke(ps.entity_id)
                raise HTTPException(status_code=403, detail={
                    "error": "handshake_denied",
                    "reason": verdict.reason,
                    "confidence": verdict.confidence,
                })
                
            permit_token = handshake_mgr.complete_session(ps.session_id)
            
            return {
                "session_id": ps.session_id,
                "phase": 5,
                "verdict": verdict.verdict.value,
                "confidence": verdict.confidence,
                "reason": verdict.reason,
                "permit_token": permit_token,
                "action": "PERMIT" if verdict.verdict == Verdict.ALLOW else "MONITOR",
            }
            
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported phase: {req.phase}")
            
    except HandshakeError as e:
        raise HTTPException(status_code=403, detail={"error": "handshake_failed", "reason": str(e)})
 
 
@app.post("/api/trust/evaluate")
async def trust_evaluate(req: TrustEvalReq, request: Request):
    REQ_COUNT.labels("trust_evaluate").inc()
    
    anomalies_data = req.anomalies
    if isinstance(anomalies_data, list):
        anomalies_data = {}
        
    source_ip = request.client.host if request.client else ""
    session_ctx = {
        "session_id": req.session_id,
        "entity_id": req.entity_id,
        "intent": req.intent,
        "source_ip": source_ip,
        "anomalies": anomalies_data,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    
    if not engine:
        raise HTTPException(status_code=503, detail="Engine not initialized")
    verdict = await engine.evaluate(session_ctx)
    return verdict.to_dict()


@app.post("/api/xdp/drop")
async def record_xdp_drop(report: XdpDropReport):
    global _xdp_drops
    _xdp_drops += report.count
    log.info("xdp_drops_reported", count=report.count, iface=report.interface,
             total=_xdp_drops)
    return {"ok": True, "total_xdp_drops": _xdp_drops}


@app.websocket("/ws/logs")
async def websocket_logs(websocket: WebSocket):
    await websocket.accept()
    log_file_path = Path("log/kelan-server.log")
    
    # Send existing logs first
    if log_file_path.exists():
        try:
            with open(log_file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
                # Send the last 150 lines
                for line in lines[-150:]:
                    await websocket.send_text(line.strip())
        except Exception as e:
            await websocket.send_text(f"2026-06-13 12:00:00 [error] Error reading initial logs: {e}")

    # Tail the log file
    try:
        with open(log_file_path, "r", encoding="utf-8") as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    await asyncio.sleep(0.15)
                    continue
                await websocket.send_text(line.strip())
    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_text(f"2026-06-13 12:00:00 [error] Error streaming logs: {e}")
        except:
            pass


@app.post("/api/trigger-attack")
async def trigger_attack():
    """Triggers the attack simulation suite in the background."""
    try:
        import sys
        import subprocess
        python_bin = sys.executable
        script_path = "scripts/run_attacks.py"
        subprocess.Popen(
            [python_bin, script_path, "--host", "localhost", "--port", "3000"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return JSONResponse({"status": "success", "message": "Attack simulation started successfully."})
    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)


@app.post("/api/trigger-enroll")
async def trigger_enroll():
    """Simulates a normal client enrollment."""
    try:
        import httpx
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "http://localhost:3000/api/enroll",
                json={
                    "entity_id": "normal-sensor-iot",
                    "intent": "Periodic telemetry reports for IoT device 01",
                    "name": "IoT-Device-01",
                    "version": 1
                },
                timeout=5.0
            )
            return JSONResponse({"status": "success", "data": resp.json()})
    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)


@app.post("/api/trigger-xdp")
async def trigger_xdp():
    """Simulates an eBPF/XDP drop event."""
    try:
        import httpx
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "http://localhost:3000/api/xdp/drop",
                json={
                    "count": 10,
                    "interface": "eth0",
                    "reason": "simulated_anomaly"
                },
                timeout=5.0
            )
            return JSONResponse({"status": "success", "data": resp.json()})
    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)


@app.get("/metrics")
async def get_metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


# ── WebSocket: Agentic Sync

@app.websocket("/ws/agent")
async def ws_agent(websocket: WebSocket):
    await websocket.accept()
    _ws_clients.add(websocket)
    client_info = f"{websocket.client.host}:{websocket.client.port}" if websocket.client else "unknown"
    log.info("agent_connected", client=client_info, total=len(_ws_clients))

    await websocket.send_json({
        "type": "connected",
        "server_version": "4.0.0-python",
        "model": cfg.ollama_model,
        "require_pq": cfg.require_pq,
    })

    try:
        while True:
            data = await websocket.receive_json()
            msg_type = data.get("type", "unknown")
            log.debug("agent_message", type=msg_type, client=client_info)
            await websocket.send_json({"type": "ack", "received": msg_type})
    except WebSocketDisconnect:
        _ws_clients.discard(websocket)
        log.info("agent_disconnected", client=client_info, remaining=len(_ws_clients))
    except Exception as exc:
        _ws_clients.discard(websocket)
        log.error("agent_ws_error", error=str(exc), client=client_info)


# ── Auth & Organization Endpoints

@app.post("/api/auth/signup")
@app.post("/api/auth/register")
async def signup(req: SignupReq, request: Request):
    enforce_rate_limit(request, limit=50, window=60)
    
    # Check if register/signup payload format is used
    email = req.email or (f"{req.entity_id}@kelan.io" if req.entity_id else None)
    password = req.password or "default_pass_123"
    
    if not email:
        raise HTTPException(status_code=400, detail="Email or entity_id is required")
        
    # Weak password validation (at least 6 chars for signup, skip for register alias)
    if req.password is not None and len(req.password) < 6:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 6 characters"
        )
        
    if email in _organisations:
        raise HTTPException(status_code=409, detail="Email already registered")
        
    org_id = str(uuid.uuid4())
    org_name = req.org_name
    password_hash = hash_password(password)
    
    org_info = {
        "id": org_id,
        "name": org_name,
        "email": email,
        "password_hash": password_hash,
        "created_at": int(time.time())
    }
    
    _organisations[email] = org_info
    
    # Issue JWT token
    now = int(time.time())
    expiry = now + (24 * 3600)  # 24 hours
    
    claims = {
        "sub": org_id,
        "org_id": org_id,
        "org_name": org_name,
        "email": email,
        "role": "admin",
        "iat": now,
        "exp": expiry,
        "nbf": now,
        "jti": str(uuid.uuid4())
    }
    
    token = encode_jwt(claims, cfg.jwt_secret)
    
    import datetime
    expires_at_iso = datetime.datetime.fromtimestamp(expiry, datetime.timezone.utc).isoformat()
    
    return {
        "token": token,
        "org": {
            "id": org_id,
            "name": org_name,
            "email": email,
            "password_hash": password_hash,
            "ollama_endpoint_enc": None,
            "trust_mode": "hybrid",
            "created_at": org_info["created_at"]
        },
        "expires_at": expires_at_iso
    }


@app.post("/api/auth/signin")
async def signin(req: SigninReq, request: Request):
    enforce_rate_limit(request, limit=50, window=60)
    
    org_info = _organisations.get(req.email)
    if not org_info or not verify_password_hash(req.password, org_info["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
        
    org_id = org_info["id"]
    org_name = org_info["name"]
    email = org_info["email"]
    
    now = int(time.time())
    expiry = now + (24 * 3600)
    
    claims = {
        "sub": org_id,
        "org_id": org_id,
        "org_name": org_name,
        "email": email,
        "role": "admin",
        "iat": now,
        "exp": expiry,
        "nbf": now,
        "jti": str(uuid.uuid4())
    }
    
    token = encode_jwt(claims, cfg.jwt_secret)
    
    import datetime
    expires_at_iso = datetime.datetime.fromtimestamp(expiry, datetime.timezone.utc).isoformat()
    
    return {
        "token": token,
        "org": {
            "id": org_id,
            "name": org_name,
            "email": email,
            "password_hash": org_info["password_hash"],
            "ollama_endpoint_enc": None,
            "trust_mode": "hybrid",
            "created_at": org_info["created_at"]
        },
        "expires_at": expires_at_iso
    }


@app.get("/api/auth/me")
async def auth_me(current_org = Depends(get_current_org)):
    org_email = current_org.get("email", "")
    org_info = _organisations.get(org_email)
    if not org_info:
        raise HTTPException(status_code=404, detail="Organisation not found")
        
    return {
        "id": org_info["id"],
        "name": org_info["name"],
        "email": org_info["email"],
        "password_hash": org_info["password_hash"],
        "ollama_endpoint_enc": None,
        "trust_mode": "hybrid",
        "created_at": org_info["created_at"]
    }


# ── Entity & Session Management Endpoints

@app.get("/api/entities")
async def list_entities(current_org = Depends(get_current_org)):
    org_id = current_org.get("org_id", "")
    from sqlalchemy import select
    async with get_session() as s:
        result = await s.execute(select(Entity).filter(Entity.org_id == org_id))
        entities = result.scalars().all()
        return [
            {
                "id": e.id,
                "org_id": e.org_id,
                "name": e.name,
                "entity_type": e.entity_type,
                "public_key": e.public_key,
                "department": e.department,
                "clearance_level": e.clearance_level,
                "allowed_intents": json.loads(str(e.allowed_intents or "[]")),
                "trust_score_avg": e.trust_score_avg,
                "session_count": e.session_count,
                "blocked_count": e.blocked_count,
                "quarantined": e.quarantined,
                "last_seen": e.last_seen,
                "enrolled_at": e.enrolled_at,
            }
            for e in entities
        ]


@app.post("/api/entities")
async def create_entity(req: CreateEntityReq, current_org = Depends(get_current_org)):
    org_id = current_org.get("org_id", "")
    
    # Basic input validation / XSS prevention
    if any(char in req.name for char in ["<", ">", "script", "javascript"]):
        raise HTTPException(status_code=400, detail="Potential XSS/HTML detected in entity name")
        
    if len(req.name) > 255:
        raise HTTPException(status_code=400, detail="Entity name too long")
        
    import secrets
    sk_bytes = secrets.token_bytes(32)
    pk_bytes = secrets.token_bytes(32)
    entity_id = secrets.token_hex(32)
    public_key_hex = pk_bytes.hex()
    private_key_hex = sk_bytes.hex()
    
    allowed_intents = req.allowed_intents or ["ModelInference", "Heartbeat", "DataSync"]
    allowed_json = json.dumps(allowed_intents)
    
    new_entity = Entity(
        id=entity_id,
        org_id=org_id,
        name=req.name,
        entity_type=req.entity_type,
        public_key=public_key_hex,
        department=req.department or "",
        clearance_level=req.clearance_level or 0,
        allowed_intents=allowed_json,
        trust_score_avg=128.0,
        session_count=0,
        blocked_count=0,
        quarantined=0,
        last_seen=None,
        enrolled_at=time.time(),
    )
    
    async with get_session() as s:
        s.add(new_entity)
        await s.commit()
        
    return {
        "entity_id": entity_id,
        "public_key": public_key_hex,
        "private_key": private_key_hex,
        "message": "Entity registered. Store the private key securely — it cannot be retrieved later."
    }


@app.get("/api/entities/{id}")
async def get_entity(id: str, current_org = Depends(get_current_org)):
    org_id = current_org.get("org_id", "")
    from sqlalchemy import select
    async with get_session() as s:
        result = await s.execute(select(Entity).filter(Entity.id == id))
        e = result.scalar_one_or_none()
        if not e:
            raise HTTPException(status_code=404, detail="Entity not found")
            
        res_sessions = await s.execute(
            select(Session)
            .filter((Session.source_entity_id == id) | (Session.dest_entity_id == id))
            .limit(20)
        )
        entity_sessions = res_sessions.scalars().all()
        
        return {
            "entity": {
                "id": e.id,
                "org_id": e.org_id,
                "name": e.name,
                "entity_type": e.entity_type,
                "public_key": e.public_key,
                "department": e.department,
                "clearance_level": e.clearance_level,
                "allowed_intents": json.loads(str(e.allowed_intents or "[]")),
                "trust_score_avg": e.trust_score_avg,
                "session_count": e.session_count,
                "blocked_count": e.blocked_count,
                "quarantined": e.quarantined,
                "last_seen": e.last_seen,
                "enrolled_at": e.enrolled_at,
            },
            "recent_sessions": [
                {
                    "id": s.id,
                    "org_id": s.org_id,
                    "source_entity_id": s.source_entity_id,
                    "dest_entity_id": s.dest_entity_id,
                    "intent": s.intent,
                    "trust_score": s.trust_score,
                    "verdict": s.verdict,
                    "ai_reasoning": s.ai_reasoning,
                    "ai_latency_ms": s.ai_latency_ms,
                    "status": s.status,
                    "bytes_tx": s.bytes_tx,
                    "bytes_rx": s.bytes_rx,
                    "anomaly_flags": s.anomaly_flags,
                    "started_at": s.started_at,
                }
                for s in entity_sessions
            ]
        }


@app.delete("/api/entities/{id}")
async def delete_entity(id: str, current_org = Depends(get_current_org)):
    org_id = current_org.get("org_id", "")
    from sqlalchemy import select, delete
    async with get_session() as s:
        result = await s.execute(select(Entity).filter(Entity.id == id))
        e = result.scalar_one_or_none()
        if not e:
            raise HTTPException(status_code=404, detail="Entity not found")
            
        await s.execute(delete(Entity).filter(Entity.id == id))
        await s.commit()
    return {"status": "deleted", "entity_id": id}


@app.put("/api/entities/{id}/quarantine")
async def quarantine_entity(id: str, current_org = Depends(get_current_org)):
    org_id = current_org.get("org_id", "")
    from sqlalchemy import select
    async with get_session() as s:
        result = await s.execute(select(Entity).filter(Entity.id == id))
        e = result.scalar_one_or_none()
        if not e:
            raise HTTPException(status_code=404, detail="Entity not found")
            
        setattr(e, "quarantined", 1)
        await s.commit()
        
    if ebpf:
        try:
            await ebpf.revoke(id)
        except Exception:
            pass
            
    return {"status": "quarantined", "entity_id": id}


@app.put("/api/entities/{id}/release")
async def release_entity(id: str, current_org = Depends(get_current_org)):
    org_id = current_org.get("org_id", "")
    from sqlalchemy import select
    async with get_session() as s:
        result = await s.execute(select(Entity).filter(Entity.id == id))
        e = result.scalar_one_or_none()
        if not e:
            raise HTTPException(status_code=404, detail="Entity not found")
            
        setattr(e, "quarantined", 0)
        await s.commit()
    return {"status": "released", "entity_id": id}


@app.post("/api/entities/{id}/test-session")
async def test_session(id: str, req: TestSessionReq, current_org = Depends(get_current_org)):
    org_id = current_org.get("org_id", "")
    
    from sqlalchemy import select
    async with get_session() as s:
        result_src = await s.execute(select(Entity).filter(Entity.id == id))
        source = result_src.scalar_one_or_none()
        if not source:
            raise HTTPException(status_code=404, detail="Source entity not found")
            
        result_dst = await s.execute(select(Entity).filter(Entity.id == req.dest_entity_id))
        dest = result_dst.scalar_one_or_none()
        if not dest:
            raise HTTPException(status_code=400, detail="Destination entity not found")
            
    session_id = str(uuid.uuid4())
    now = time.time()
    age_hours = (now - source.enrolled_at) / 3600.0 if source.enrolled_at else 24.0
    
    anomalies = {}
    behavioral_flags = []
    if req.simulate_lateral_movement:
        behavioral_flags.append("NewPeerInteraction")
        anomalies["new_peer"] = True
    if req.bytes_tx and req.bytes_tx > 10000000:
        behavioral_flags.append("ExfiltrationPattern")
        anomalies["exfiltration"] = True
        
    # Detect clearance violation
    if source.clearance_level < dest.clearance_level:
        behavioral_flags.append("ClearanceViolation")
        anomalies["clearance_violation"] = True
        
    # Detect control signal abuse
    if req.intent == "ControlSignal":
        behavioral_flags.append("ControlSignalAbuse")
        anomalies["control_signal_abuse"] = True
        
    if ("CONTROL" in req.intent.upper() or "ADMIN" in req.intent.upper()) and source.clearance_level < 3:
        anomalies["control_signal_abuse"] = True
        if "ControlSignalAbuse" not in behavioral_flags:
            behavioral_flags.append("ControlSignalAbuse")
        
    session_ctx = {
        "session_id": session_id,
        "entity_id": id,
        "intent": req.intent,
        "source_ip": "127.0.0.1",
        "anomalies": anomalies,
        "org_id": org_id,
        "source_entity_type": source.entity_type,
        "source_department": source.department,
        "source_clearance": source.clearance_level,
        "dest_entity_id": req.dest_entity_id,
        "dest_entity_type": dest.entity_type,
        "entity_age_hours": age_hours,
        "session_count_24h": source.session_count,
        "avg_trust_score": source.trust_score_avg,
        "known_peer": True,
        "clearance_violation": anomalies.get("clearance_violation", False),
        "control_signal_abuse": anomalies.get("control_signal_abuse", False),
        "behavioral_flags": behavioral_flags,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    
    if not engine:
        raise HTTPException(status_code=503, detail="Engine not initialized")
        
    verdict = await engine.evaluate(session_ctx)
    VERDICT_COUNT.labels(verdict.verdict.value).inc()
    
    async with get_session() as s:
        new_session = Session(
            id=session_id,
            entity_id=id,
            org_id=org_id,
            source_entity_id=id,
            dest_entity_id=req.dest_entity_id,
            intent=req.intent,
            trust_score=180 if verdict.verdict == Verdict.ALLOW else (100 if verdict.verdict == Verdict.MONITOR else 50),
            verdict=verdict.verdict.value,
            ai_reasoning=verdict.reason,
            ai_latency_ms=verdict.latency_ms,
            status="Active" if verdict.verdict != Verdict.DENY else "Blocked",
            bytes_tx=req.bytes_tx or 0,
            bytes_rx=0,
            anomaly_flags=",".join(behavioral_flags),
            started_at=now,
        )
        s.add(new_session)
        
        source_db = await s.get(Entity, id)
        if source_db:
            session_cnt = getattr(source_db, "session_count", 0)
            if not isinstance(session_cnt, int):
                session_cnt = 0
            setattr(source_db, "session_count", session_cnt + 1)
            
            if verdict.verdict == Verdict.DENY:
                blocked_cnt = getattr(source_db, "blocked_count", 0)
                if not isinstance(blocked_cnt, int):
                    blocked_cnt = 0
                setattr(source_db, "blocked_count", blocked_cnt + 1)
                
        await s.commit()
        
    return {
        "session_id": session_id,
        "verdict": verdict.verdict.value,
        "trust_score": 180 if verdict.verdict == Verdict.ALLOW else (100 if verdict.verdict == Verdict.MONITOR else 50),
        "reasoning": verdict.reason,
        "primary_risk": "None" if verdict.verdict == Verdict.ALLOW else "Suspicious session",
        "evaluation_source": "ollama" if verdict.from_cache is False else "cache",
    }


@app.get("/api/sessions")
async def list_sessions(current_org = Depends(get_current_org)):
    org_id = current_org.get("org_id", "")
    from sqlalchemy import select
    async with get_session() as s:
        result = await s.execute(select(Session).filter(Session.org_id == org_id))
        sessions = result.scalars().all()
        return [
            {
                "id": s.id,
                "org_id": s.org_id,
                "source_entity_id": s.source_entity_id,
                "dest_entity_id": s.dest_entity_id,
                "intent": s.intent,
                "trust_score": s.trust_score,
                "verdict": s.verdict,
                "ai_reasoning": s.ai_reasoning,
                "ai_latency_ms": s.ai_latency_ms,
                "status": s.status,
                "bytes_tx": s.bytes_tx,
                "bytes_rx": s.bytes_rx,
                "anomaly_flags": s.anomaly_flags,
                "started_at": s.started_at,
            }
            for s in sessions
        ]


@app.post("/api/config/verify-key")
async def verify_key(req: VerifyKeyReq, current_org = Depends(get_current_org)):
    if not engine or not engine.ollama:
        return JSONResponse(status_code=503, content={
            "error": "ollama_unavailable",
            "detail": "Engine or Ollama client not initialized"
        })
        
    test_ctx = {
        "entity_id": "test_entity_abc123",
        "intent": "ModelInference",
        "session_id": "verify_session",
        "anomalies": {},
        "name": "VerifyKeyTest",
        "version": 1,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    
    old_model = engine.ollama.model
    if req.model:
        engine.ollama.model = req.model
        
    try:
        verdict = await engine.ollama.evaluate(test_ctx)
        if verdict.reason.startswith("ollama_error:"):
            raise Exception(verdict.reason)
            
        return {
            "status": "verified",
            "provider": req.provider,
            "model": req.model,
            "test_evaluation": {
                "trust_score": 180,
                "verdict": verdict.verdict.value,
                "reasoning": verdict.reason,
                "confidence": verdict.confidence,
                "evaluation_ms": verdict.latency_ms,
            }
        }
    except Exception as exc:
        log.error("ollama_verification_failed", error=str(exc))
        return JSONResponse(status_code=503, content={
            "error": "ollama_unavailable",
            "detail": str(exc)[:120]
        })
    finally:
        engine.ollama.model = old_model
