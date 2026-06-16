"""
AITP 5-Phase Handshake — pure Python.
Replaces the Rust aitp-core handshake FSM.

Phase 1 — SYN:         client → server (entity_id, kem_pk, x25519_pk)
Phase 2 — SYN-ACK:     server → client (kem_ct, x25519_pk)
Phase 3 — KEM-COMPLETE: client → server (kem_ct, sig)
Phase 4 — AI-EVAL:     server internal (Ollama verdict)
Phase 5 — COMPLETE:    server → client (permit_token) + PERMIT_MAP write
"""
import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional

from .crypto import (
    ed25519_verify, is_valid_ed25519_sig,
    x25519_generate, x25519_exchange,
    kem_encapsulate, derive_session_key,
)


class Phase(IntEnum):
    INIT         = 0
    SYN          = 1
    SYN_ACK      = 2
    KEM_COMPLETE = 3
    AI_EVAL      = 4
    COMPLETE     = 5


class HandshakeError(Exception):
    pass


@dataclass
class PendingSession:
    session_id:       str
    entity_id:        str
    intent:           str
    nonce_c:          str
    kem_pk_c:         Optional[bytes]
    x25519_pk_c:      Optional[bytes]
    phase:            Phase = Phase.SYN
    # server-side ephemeral keys
    x25519_sk_s:      bytes = field(default_factory=lambda: os.urandom(32))
    x25519_pk_s:      bytes = field(default_factory=lambda: os.urandom(32))
    kem_ct_s:         Optional[bytes] = None
    session_key:      Optional[bytes] = None
    transcript_hash:  Optional[str]   = None
    created_at:       float = field(default_factory=time.time)

    def is_expired(self, ttl: float = 60.0) -> bool:
        return time.time() - self.created_at > ttl


class HandshakeManager:
    """
    Manages all pending AITP handshake sessions.
    Thread-safe for asyncio single-thread model.
    """

    def __init__(self, require_pq: bool = True):
        self.require_pq = require_pq
        self._pending: dict[str, PendingSession] = {}

    # ── Phase 1: receive SYN 
    def receive_syn(
        self,
        entity_id:       str,
        intent:          str,
        nonce_c:         str,
        x25519_pk_c_hex: Optional[str],
        kem_pk_c_hex:    Optional[str],
    ) -> PendingSession:
        if self.require_pq and not kem_pk_c_hex:
            raise HandshakeError("ML-KEM public key required (require_pq=true)")

        session_id = str(uuid.uuid4())
        kem_pk_c   = bytes.fromhex(kem_pk_c_hex)  if kem_pk_c_hex   else None
        x25519_pk_c= bytes.fromhex(x25519_pk_c_hex) if x25519_pk_c_hex else None

        # Generate server ephemeral X25519 keypair
        x25519_sk_s, x25519_pk_s = x25519_generate()

        # Encapsulate ML-KEM against client public key
        kem_ct_s = None
        if kem_pk_c:
            kem_ct_s, _ = kem_encapsulate(kem_pk_c)

        ps = PendingSession(
            session_id   = session_id,
            entity_id    = entity_id,
            intent       = intent,
            nonce_c      = nonce_c,
            kem_pk_c     = kem_pk_c,
            x25519_pk_c  = x25519_pk_c,
            x25519_sk_s  = x25519_sk_s,
            x25519_pk_s  = x25519_pk_s,
            kem_ct_s     = kem_ct_s,
            phase        = Phase.SYN,
        )
        self._pending[session_id] = ps
        return ps

    # ── Phase 3: receive KEM-COMPLETE ─────────────────────────
    def receive_kem_complete(
        self,
        session_id:      str,
        kem_ct_c_hex:    str,
        signature_hex:   str,
        ed25519_pk_hex:  str,
    ) -> PendingSession:
        ps = self._pending.get(session_id)
        if not ps:
            raise HandshakeError(f"Unknown session: {session_id}")
        if ps.is_expired():
            del self._pending[session_id]
            raise HandshakeError("Session expired")
        if ps.phase != Phase.SYN:
            raise HandshakeError(f"Wrong phase: expected SYN, got {ps.phase}")

        # Validate signature
        if not is_valid_ed25519_sig(signature_hex):
            raise HandshakeError("Invalid Ed25519 signature (zero/invalid)")

        transcript = json.dumps({
            "session_id": session_id,
            "entity_id":  ps.entity_id,
            "nonce_c":    ps.nonce_c,
        }, sort_keys=True).encode()

        sig    = bytes.fromhex(signature_hex)
        ed_pub = bytes.fromhex(ed25519_pk_hex)
        if not ed25519_verify(ed_pub, sig, transcript):
            raise HandshakeError("Ed25519 signature verification FAILED — identity spoofing attempt")

        # Derive session key
        kem_ct_c = bytes.fromhex(kem_ct_c_hex)
        x25519_shared = b"\x00" * 32
        if ps.x25519_pk_c:
            x25519_shared = x25519_exchange(ps.x25519_sk_s, ps.x25519_pk_c)

        ps.session_key = derive_session_key(
            kem_ct_c[:32],   # simplified — real impl decapsulates
            x25519_shared,
        )
        ps.transcript_hash = hashlib.sha256(transcript).hexdigest()
        ps.phase = Phase.KEM_COMPLETE
        return ps

    # ── Phase 5: complete (after AI verdict = ALLOW) ──────────
    def complete_session(self, session_id: str) -> str:
        ps = self._pending.pop(session_id, None)
        if not ps:
            raise HandshakeError(f"Session not found: {session_id}")
        ps.phase = Phase.COMPLETE
        return str(uuid.uuid4())   # permit_token

    # ── Cleanup 
    def purge_expired(self):
        expired = [sid for sid, ps in self._pending.items() if ps.is_expired()]
        for sid in expired:
            del self._pending[sid]
