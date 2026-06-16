"""Unit tests for Kelan crypto identity and KEM wrappers."""
from kelan.crypto.identity import generate_keypair, sign, verify
from kelan.crypto.kem import mlkem_keygen, mlkem_encap, mlkem_decap

def test_identity_signature_roundtrip():
    sk, pk = generate_keypair()
    msg = b"identity verification message"
    sig = sign(sk, msg)
    assert verify(pk, msg, sig) is True

def test_identity_wrong_message_fails():
    sk, pk = generate_keypair()
    msg = b"identity verification message"
    sig = sign(sk, msg)
    assert verify(pk, b"tampered message", sig) is False

def test_identity_wrong_key_fails():
    sk1, pk1 = generate_keypair()
    sk2, pk2 = generate_keypair()
    msg = b"identity verification message"
    sig = sign(sk1, msg)
    assert verify(pk2, msg, sig) is False

def test_mlkem_roundtrip():
    pk, sk = mlkem_keygen()
    ct, ss1 = mlkem_encap(pk)
    ss2 = mlkem_decap(sk, ct)
    assert isinstance(ss1, bytes) and len(ss1) >= 32
    assert isinstance(ss2, bytes) and len(ss2) >= 32

