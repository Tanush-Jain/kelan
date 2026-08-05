"""
eBPF Bridge — Python controls Rust XDP pipeline via subprocess.
Rust does ONE thing: load XDP into kernel and manage BPF maps.
Python decides WHAT to permit/deny via Ollama.
"""
import asyncio
import json
from pathlib import Path
from typing import Optional
import structlog

log = structlog.get_logger()

LOADER_BINARY = Path(__file__).parent.parent.parent / \
    "target/release/kelan-ebpf-loader"


class EbpfBridge:

    def __init__(self, iface: str = "eth0"):
        self.iface  = iface
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._mode  = "software"

    async def start(self):
        if not LOADER_BINARY.exists():
            log.warning("ebpf_binary_missing",
                        path=str(LOADER_BINARY),
                        mode="software_fallback")
            self._mode = "software"
            return

        try:
            self._proc = await asyncio.create_subprocess_exec(
                str(LOADER_BINARY),
                "--interface", self.iface,
                "--ipc-mode", "stdin",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._mode = "ebpf"
            log.info("ebpf_started", pid=self._proc.pid, iface=self.iface)
        except Exception as exc:
            log.warning("ebpf_start_failed", error=str(exc), mode="software")
            self._mode = "software"

    async def permit(self, session_id: str, entity_id: str, src_ip: str = ""):
        await self._cmd({"action": "PERMIT", "session_id": session_id,
                         "entity_id": entity_id, "src_ip": src_ip})

    async def revoke(self, entity_id: str):
        await self._cmd({"action": "REVOKE", "entity_id": entity_id})

    async def drop_stats(self) -> dict:
        if self._mode == "software":
            return {}
        # Read from /proc or BPF map via bpftool
        try:
            proc = await asyncio.create_subprocess_exec(
                "bpftool", "map", "dump", "name", "SYN_RATE",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
            )
            out, _ = await proc.communicate()
            return {"raw": out.decode()[:200]}
        except Exception:
            return {}

    async def _cmd(self, payload: dict):
        if self._proc and self._proc.stdin:
            try:
                line = json.dumps(payload).encode() + b"\n"
                self._proc.stdin.write(line)
                await self._proc.stdin.drain()
                log.debug("ebpf_cmd", **payload)
            except Exception as exc:
                log.error("ebpf_cmd_failed", error=str(exc))
        else:
            log.debug("ebpf_software_mode", action=payload.get("action"))

    @property
    def mode(self) -> str:
        return self._mode

    async def stop(self):
        if self._proc:
            self._proc.terminate()
            await self._proc.wait()
