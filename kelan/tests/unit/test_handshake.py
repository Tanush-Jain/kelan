"""Unit tests for the AITP handshake protocol."""
import json
import pytest
from kelan.protocol.handshake import HandshakeManager, HandshakeError, Phase, PendingSession
from kelan.protocol.crypto import ed25519_generate, ed25519_sign, x25519_generate

def test_pending_session_expiration():
    sess = PendingSession(
        session_id="test-sess",
        entity_id="test-entity",
        intent="test-intent",
        nonce_c="nonce",
        kem_pk_c=None,
        x25519_pk_c=None,
    )
    assert sess.is_expired(ttl=60) is False
    # Artificially age the session
    sess.created_at -= 61
    assert sess.is_expired(ttl=60) is True

def test_receive_syn_requires_pq():
    mgr = HandshakeManager(require_pq=True)
    with pytest.raises(HandshakeError) as exc_info:
        mgr.receive_syn("entity-1", "intent-1", "nonce-1", "x25519-pk", None)
    assert "ML-KEM public key required" in str(exc_info.value)

def test_receive_syn_success():
    mgr = HandshakeManager(require_pq=False)
    _, x25519_pub = x25519_generate()
    
    # KEM public key is typically 1184 bytes, let's use a dummy hex representation
    kem_pub_hex = "00" * 1184
    
    ps = mgr.receive_syn(
        entity_id="entity-1",
        intent="intent-1",
        nonce_c="nonce-1",
        x25519_pk_c_hex=x25519_pub.hex(),
        kem_pk_c_hex=kem_pub_hex,
    )
    
    assert ps.session_id in mgr._pending
    assert ps.entity_id == "entity-1"
    assert ps.intent == "intent-1"
    assert ps.nonce_c == "nonce-1"
    assert ps.phase == Phase.SYN
    assert ps.kem_ct_s is not None
    assert ps.x25519_pk_s is not None

def test_receive_kem_complete_unknown_session():
    mgr = HandshakeManager(require_pq=False)
    with pytest.raises(HandshakeError) as exc_info:
        mgr.receive_kem_complete("unknown-session", "kem-ct", "sig", "pubkey")
    assert "Unknown session" in str(exc_info.value)

def test_receive_kem_complete_expired():
    mgr = HandshakeManager(require_pq=False)
    ps = mgr.receive_syn("entity-1", "intent-1", "nonce-1", None, None)
    ps.created_at -= 61 # Expire it
    
    with pytest.raises(HandshakeError) as exc_info:
        mgr.receive_kem_complete(ps.session_id, "00"*1088, "00"*64, "00"*32)
    assert "Session expired" in str(exc_info.value)
    assert ps.session_id not in mgr._pending

def test_receive_kem_complete_wrong_phase():
    mgr = HandshakeManager(require_pq=False)
    ps = mgr.receive_syn("entity-1", "intent-1", "nonce-1", None, None)
    ps.phase = Phase.KEM_COMPLETE # Change phase manually
    
    with pytest.raises(HandshakeError) as exc_info:
        mgr.receive_kem_complete(ps.session_id, "00"*1088, "00"*64, "00"*32)
    assert "Wrong phase" in str(exc_info.value)

def test_receive_kem_complete_invalid_sig_format():
    mgr = HandshakeManager(require_pq=False)
    ps = mgr.receive_syn("entity-1", "intent-1", "nonce-1", None, None)
    
    # 00*64 is rejected by is_valid_ed25519_sig
    with pytest.raises(HandshakeError) as exc_info:
        mgr.receive_kem_complete(ps.session_id, "00"*1088, "00"*64, "00"*32)
    assert "Invalid Ed25519 signature" in str(exc_info.value)

def test_receive_kem_complete_sig_verification_fail():
    mgr = HandshakeManager(require_pq=False)
    ps = mgr.receive_syn("entity-1", "intent-1", "nonce-1", None, None)
    
    priv, pub = ed25519_generate()
    # Sign random transcript instead of actual
    sig = ed25519_sign(priv, b"different transcript")
    
    with pytest.raises(HandshakeError) as exc_info:
        mgr.receive_kem_complete(ps.session_id, "00"*1088, sig.hex(), pub.hex())
    assert "signature verification FAILED" in str(exc_info.value)

def test_receive_kem_complete_success():
    mgr = HandshakeManager(require_pq=False)
    _, x25519_pub_c = x25519_generate()
    
    ps = mgr.receive_syn(
        entity_id="entity-1",
        intent="intent-1",
        nonce_c="nonce-1",
        x25519_pk_c_hex=x25519_pub_c.hex(),
        kem_pk_c_hex=None,
    )
    
    priv_e, pub_e = ed25519_generate()
    transcript = json.dumps({
        "session_id": ps.session_id,
        "entity_id":  "entity-1",
        "nonce_c":    "nonce-1",
    }, sort_keys=True).encode()
    sig = ed25519_sign(priv_e, transcript)
    
    ps_updated = mgr.receive_kem_complete(
        session_id=ps.session_id,
        kem_ct_c_hex=("00"*1088),
        signature_hex=sig.hex(),
        ed25519_pk_hex=pub_e.hex(),
    )
    
    assert ps_updated.phase == Phase.KEM_COMPLETE
    assert ps_updated.session_key is not None
    assert ps_updated.transcript_hash is not None

def test_complete_session_not_found():
    mgr = HandshakeManager()
    with pytest.raises(HandshakeError) as exc_info:
        mgr.complete_session("non-existent")
    assert "Session not found" in str(exc_info.value)

def test_complete_session_success():
    mgr = HandshakeManager(require_pq=False)
    ps = mgr.receive_syn("entity-1", "intent-1", "nonce-1", None, None)
    token = mgr.complete_session(ps.session_id)
    assert token is not None
    assert ps.session_id not in mgr._pending
    assert ps.phase == Phase.COMPLETE

def test_purge_expired():
    mgr = HandshakeManager(require_pq=False)
    ps1 = mgr.receive_syn("entity-1", "intent-1", "nonce-1", None, None)
    ps2 = mgr.receive_syn("entity-2", "intent-2", "nonce-2", None, None)
    
    ps1.created_at -= 100 # Expired
    mgr.purge_expired()
    
    assert ps1.session_id not in mgr._pending
    assert ps2.session_id in mgr._pending
