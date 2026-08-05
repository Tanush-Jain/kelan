import asyncio
import os
import sys
import subprocess
import uvicorn
import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path

app = FastAPI(title="Kelan Security Dashboard Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

PROJECT_ROOT = Path(__file__).parent.parent
DASHBOARD_HTML_PATH = PROJECT_ROOT / "static" / "dashboard.html"
LOG_FILE_PATH = PROJECT_ROOT / "log" / "kelan-server.log"

@app.get("/")
async def get_dashboard():
    if not DASHBOARD_HTML_PATH.exists():
        return HTMLResponse("Dashboard UI file not found at static/dashboard.html. Please ensure it is created.", status_code=404)
    with open(DASHBOARD_HTML_PATH, "r", encoding="utf-8") as f:
        html = f.read()
    return HTMLResponse(html)

@app.websocket("/ws/logs")
async def websocket_logs(websocket: WebSocket):
    await websocket.accept()
    
    # Send existing logs first
    if LOG_FILE_PATH.exists():
        try:
            with open(LOG_FILE_PATH, "r", encoding="utf-8") as f:
                lines = f.readlines()
                # Send the last 150 lines
                for line in lines[-150:]:
                    await websocket.send_text(line.strip())
        except Exception as e:
            await websocket.send_text(f"2026-06-13 12:00:00 [error] Error reading initial logs: {e}")

    # Tail the log file
    try:
        with open(LOG_FILE_PATH, "r", encoding="utf-8") as f:
            # Go to the end
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
        # Resolve python bin
        python_bin = sys.executable
        script_path = str(PROJECT_ROOT / "scripts" / "run_attacks.py")
        
        # Run run_attacks.py as a subprocess
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

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=7681, log_level="warning")
