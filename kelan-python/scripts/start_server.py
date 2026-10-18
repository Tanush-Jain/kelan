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
                             Python Engine v3.0
    ═══════════════════════════════════════════════════════════
    [HOST]        {settings.bind_host}
    [PORT]        {settings.http_port}
    [MODE]        {settings.mode}
    [OLLAMA]      {settings.ollama_endpoint} ({settings.ollama_model})
    [POST-QUANT]  {"REQUIRED" if settings.require_pq else "DISABLED"}
    [eBPF BRIDGE] {"ENABLED" if settings.ebpf_enabled else "DISABLED"}
    ═══════════════════════════════════════════════════════════
    """
    print(banner)

if __name__ == "__main__":
    settings = get_settings()
    print_banner(settings)
    uvicorn.run("kelan.server.main:app", host=settings.bind_host, port=settings.http_port, reload=True)
