from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import os
from pathlib import Path
import time
from typing import Any, cast

import structlog
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    REGISTRY,
    Counter,
    generate_latest,
)
from starlette.responses import Response

from ..ai.ollama_client import OllamaClient
from ..config import get_settings

log = structlog.get_logger()
cfg = get_settings()

if "kelan_requests_total" in REGISTRY._names_to_collectors:
    REQ_COUNT = cast(Counter, REGISTRY._names_to_collectors["kelan_requests_total"])
else:
    REQ_COUNT = Counter("kelan_requests_total", "Total requests", ["endpoint"])

if "kelan_api_verdicts_total" in REGISTRY._names_to_collectors:
    VERDICT_COUNT = cast(Counter, REGISTRY._names_to_collectors["kelan_api_verdicts_total"])
else:
    VERDICT_COUNT = Counter("kelan_api_verdicts_total", "Verdicts", ["verdict"])

ollama: OllamaClient | None = None
_start_time = time.time()
_verdict_buf: list[dict[str, Any]] = []
_MAX_BUF = 1000
_ws_clients: set[WebSocket] = set()


@asynccontextmanager
async def lifespan(app: FastAPI):
    global ollama
    log.info("kelan_community_starting", port=cfg.http_port, model=cfg.ollama_model)
    ollama = OllamaClient(
        cfg.ollama_endpoint,
        cfg.ollama_model,
        cfg.ollama_timeout,
        cfg.ollama_temperature,
    )
    ok = await ollama.ping()
    log.info("ollama_status", connected=ok, model=cfg.ollama_model, endpoint=cfg.ollama_endpoint)
    yield
    await ollama.close()
    log.info("kelan_community_stopped")


app = FastAPI(
    title="Kelan Community Security Scanner",
    description="Community Edition — Audit-only scanner, local reports, and metrics",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

if os.path.exists("kelan-dashboard/dist/assets"):
    from fastapi.staticfiles import StaticFiles
    app.mount("/assets", StaticFiles(directory="kelan-dashboard/dist/assets"), name="assets")


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


def _get_dashboard_file() -> Path | None:
    candidates = [
        Path("kelan-dashboard/dist/index.html"),
        Path("static/dashboard.html"),
        Path("static/index.html"),
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


@app.get("/")
@app.get("/dashboard")
async def get_dashboard():
    f = _get_dashboard_file()
    if f:
        return FileResponse(str(f))
    return HTMLResponse("<h1>Kelan Community Scanner</h1><p>Audit mode active.</p>")


@app.get("/terminal")
@app.get("/logs/terminal.html")
@app.get("/log/terminal.html")
async def get_terminal():
    p = Path("static/terminal.html")
    if p.exists():
        return FileResponse(str(p))
    return HTMLResponse("<h1>Kelan Terminal Logs</h1><p>Terminal log viewer.</p>")


@app.get("/health")
@app.get("/api/health")
async def health():
    REQ_COUNT.labels(endpoint="/api/health").inc()
    return {
        "status": "ok",
        "edition": "community",
        "mode": "audit",
        "version": "0.1.0",
        "uptime_seconds": time.time() - _start_time,
        "ollama_connected": bool(ollama),
    }


@app.get("/api/stats")
async def get_stats():
    REQ_COUNT.labels(endpoint="/api/stats").inc()
    return {
        "edition": "community",
        "mode": "audit",
        "total_verdicts": len(_verdict_buf),
        "uptime_seconds": time.time() - _start_time,
        "active_enforcement": False,
    }


@app.get("/api/verdicts")
async def get_verdicts():
    REQ_COUNT.labels(endpoint="/api/verdicts").inc()
    return {
        "verdicts": list(_verdict_buf),
        "count": len(_verdict_buf),
    }


@app.get("/metrics")
async def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.websocket("/ws/telemetry")
async def ws_telemetry(websocket: WebSocket):
    await websocket.accept()
    _ws_clients.add(websocket)
    try:
        while True:
            await asyncio.sleep(1)
            await websocket.send_json({
                "type": "heartbeat",
                "uptime": time.time() - _start_time,
                "mode": "audit",
            })
    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    finally:
        _ws_clients.discard(websocket)
