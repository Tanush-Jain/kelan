import uvicorn
import sys
from pathlib import Path

# Add project root to sys.path so we can import kelan
sys.path.append(str(Path(__file__).parent.parent))

from kelan.config import get_settings

def print_banner(settings):
    banner = f"""
    ═══════════════════════════════════════════════════════════
       █   █ █▀▀▀█ █    █▀▀▀█ █    █   █▀▀▀█ █▀▀▀█ █▀▀▀█ █▀▀▀█ 
       ██▄▄█ █▄▄▄█ █    █▄▄▄█ █ ▄  █   ▄▄▄▄█ █▄▄▄█ █   █ █▄▄▄█ 
       █   █ █▄▄▄▄ █▄▄▄ █   █ █▄██▄█   █▄▄▄▄ █     █▄▄▄█ █▄▄▄▄ 
    ═══════════════════════════════════════════════════════════
                    Adaptive Intent Transport Protocol
                             Python Engine v4.0
    ═══════════════════════════════════════════════════════════
    [HOST]        {settings.host}
    [PORT]        {settings.http_port}
    [OLLAMA]      {settings.ollama_endpoint} ({settings.ollama_model})
    [POST-QUANT]  {"REQUIRED" if settings.require_pq else "DISABLED"}
    [DEBUG]       {"ENABLED" if settings.debug else "DISABLED"}
    ═══════════════════════════════════════════════════════════
    """
    print(banner)

if __name__ == "__main__":
    import os
    settings = get_settings()
    os.makedirs(getattr(settings, "DATA_DIR", "data"), exist_ok=True)
    print_banner(settings)
    uvicorn.run("kelan.api.server:app", host=settings.host, port=settings.http_port, reload=False)
