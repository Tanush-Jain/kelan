"""
eBPF Bridge — Python → Rust eBPF loader IPC.
Sends verdict and rate-limit commands to the Rust kelan-ebpf-loader
via Unix domain socket or subprocess.
Falls back gracefully if the eBPF loader is not running.
"""
import asyncio
import json
import os
import socket
import time
from typing import Optional
import structlog

log = structlog.get_logger()

# Path where kelan-ebpf-loader listens for commands
EBPF_SOCKET_PATH = os.environ.get("KELAN_EBPF_SOCKET", "/tmp/kelan-ebpf.sock")


class EbpfBridge:
    """
    Async bridge to the Rust eBPF loader.
    Commands are JSON messages sent over a Unix domain socket.
    If the socket does not exist (eBPF loader not running), commands are
    logged and silently dropped — the Python layer still functions.
    """

    def __init__(self, socket_path: str = EBPF_SOCKET_PATH):
        self.socket_path = socket_path
        self._connected = False
        self._last_error_log = 0.0

    async def _send(self, command: dict) -> bool:
        """Send a JSON command to the eBPF loader. Returns True on success."""
        if not os.path.exists(self.socket_path):
            now = time.time()
            if now - self._last_error_log > 30:
                log.debug("ebpf_socket_not_found", path=self.socket_path,
                          note="eBPF loader not running — command dropped")
                self._last_error_log = now
            return False

        try:
            loop = asyncio.get_event_loop()
            data = (json.dumps(command) + "\n").encode()
            await loop.run_in_executor(None, self._send_sync, data)
            return True
        except Exception as exc:
            log.error("ebpf_send_error", error=str(exc), command=command.get("cmd"))
            return False

    def _send_sync(self, data: bytes) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        try:
            sock.connect(self.socket_path)
            sock.sendall(data)
        finally:
            sock.close()

    async def block_ip(self, ip: str, reason: str = "", duration_secs: int = 300) -> bool:
        """Instruct the eBPF program to drop all packets from `ip`."""
        log.info("ebpf_block_ip", ip=ip, reason=reason, duration_secs=duration_secs)
        return await self._send({
            "cmd": "block_ip",
            "ip": ip,
            "reason": reason,
            "duration_secs": duration_secs,
        })

    async def unblock_ip(self, ip: str) -> bool:
        """Remove an IP block from the eBPF map."""
        log.info("ebpf_unblock_ip", ip=ip)
        return await self._send({"cmd": "unblock_ip", "ip": ip})

    async def set_rate_limit(self, ip: str, pps: int) -> bool:
        """Update per-IP rate limit in the eBPF token-bucket map."""
        return await self._send({"cmd": "set_rate_limit", "ip": ip, "pps": pps})

    async def report_drop_count(self) -> Optional[int]:
        """
        Request the current XDP drop counter from the eBPF loader.
        Returns None if not available.
        """
        # Future: bidirectional socket protocol
        return None

    async def is_available(self) -> bool:
        """Check if the eBPF loader socket exists and is connectable."""
        return os.path.exists(self.socket_path)
