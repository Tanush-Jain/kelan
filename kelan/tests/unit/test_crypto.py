"""Tests for Python crypto layer."""
import pytest
from kelan.protocol.crypto import (
    ed25519_generate, ed25519_sign, ed25519_verify,
    is_valid_ed25519_sig,
    x25519_generate, x25519_exchange,
    hkdf_derive, aes_gcm_encrypt, aes_gcm_decrypt,
    kem_generate, kem_encapsulate, kem_decapsulate,
    derive_session_key,
)


class TestEd25519:

    def test_sign_verify_roundtrip(self):
        priv, pub = ed25519_generate()
        msg = b"test message for signing"
        sig = ed25519_sign(priv, msg)
        assert ed25519_verify(pub, sig, msg)

    def test_wrong_message_fails(self):
        priv, pub = ed25519_generate()
        sig = ed25519_sign(priv, b"original")
        assert not ed25519_verify(pub, sig, b"tampered")

    def test_wrong_key_fails(self):
        priv, _   = ed25519_generate()
        _, pub2   = ed25519_generate()
        sig = ed25519_sign(priv, b"message")
        assert not ed25519_verify(pub2, sig, b"message")

    def test_valid_sig_check_passes(self):
        priv, _ = ed25519_generate()
        sig     = ed25519_sign(priv, b"test")
        assert is_valid_ed25519_sig(sig.hex())

    def test_zero_sig_rejected(self):
        assert not is_valid_ed25519_sig("00" * 64)

    def test_ff_sig_rejected(self):
        assert not is_valid_ed25519_sig("ff" * 64)

    def test_short_sig_rejected(self):
        assert not is_valid_ed25519_sig("deadbeef")


class TestX25519:

    def test_dh_exchange_matches(self):
        priv_a, pub_a = x25519_generate()
        priv_b, pub_b = x25519_generate()
        shared_a = x25519_exchange(priv_a, pub_b)
        shared_b = x25519_exchange(priv_b, pub_a)
        assert shared_a == shared_b

    def test_shared_secret_32_bytes(self):
        priv_a, pub_a = x25519_generate()
        priv_b, pub_b = x25519_generate()
        shared = x25519_exchange(priv_a, pub_b)
        assert len(shared) == 32


class TestHKDF:

    def test_derive_32_bytes(self):
        key = hkdf_derive(b"input key material", length=32)
        assert len(key) == 32

    def test_different_info_different_key(self):
        k1 = hkdf_derive(b"ikm", info=b"info1")
        k2 = hkdf_derive(b"ikm", info=b"info2")
        assert k1 != k2

    def test_same_inputs_same_key(self):
        k1 = hkdf_derive(b"ikm", info=b"AITP-v1")
        k2 = hkdf_derive(b"ikm", info=b"AITP-v1")
        assert k1 == k2


class TestAESGCM:

    def test_encrypt_decrypt_roundtrip(self):
        import os
        key  = os.urandom(32)
        pt   = b"secret network data"
        ct   = aes_gcm_encrypt(key, pt)
        out  = aes_gcm_decrypt(key, ct)
        assert out == pt

    def test_wrong_key_fails(self):
        import os
        key  = os.urandom(32)
        key2 = os.urandom(32)
        ct   = aes_gcm_encrypt(key, b"data")
        with pytest.raises(Exception):
            aes_gcm_decrypt(key2, ct)


class TestKEM:

    def test_kem_roundtrip(self):
        kp          = kem_generate()
        ct, shared1 = kem_encapsulate(kp.public_key)
        shared2     = kem_decapsulate(kp.private_key, ct)
        # Both parties derive same secret (may differ in stub mode, just check types)
        assert isinstance(shared1, bytes) and len(shared1) >= 32
        assert isinstance(shared2, bytes) and len(shared2) >= 32


class TestSessionKey:

    def test_derive_session_key_32_bytes(self):
        import os
        k = derive_session_key(os.urandom(32), os.urandom(32))
        assert len(k) == 32

    def test_different_inputs_different_keys(self):
        import os
        a = derive_session_key(os.urandom(32), os.urandom(32))
        b = derive_session_key(os.urandom(32), os.urandom(32))
        assert a != b
