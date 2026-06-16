"""
Kelan Cryptography — Pure Python.
Replaces kelan-crypto Rust crate entirely.
  • Ed25519  — identity signing / verification
  • X25519   — ephemeral key exchange
  • ML-KEM stub — post-quantum KEM (real impl via kyber-py if installed)
  • AES-256-GCM — session encryption
  • HKDF-SHA256 — key derivation
"""
import os
import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


# ── Ed25519 
def ed25519_generate() -> tuple[bytes, bytes]:
    """Returns (private_bytes, public_bytes)."""
    priv = Ed25519PrivateKey.generate()
    priv_b = priv.private_bytes_raw()
    pub_b  = priv.public_key().public_bytes_raw()
    return priv_b, pub_b


def ed25519_sign(private_bytes: bytes, message: bytes) -> bytes:
    priv = Ed25519PrivateKey.from_private_bytes(private_bytes)
    return priv.sign(message)


def ed25519_verify(public_bytes: bytes, signature: bytes, message: bytes) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(public_bytes)
        pub.verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def is_valid_ed25519_sig(sig_hex: str) -> bool:
    """Quick check — rejects all-zero or all-F signatures."""
    if not sig_hex or len(sig_hex) < 128:
        return False
    sig = sig_hex.lower()
    if sig == "00" * 64 or sig == "ff" * 64:
        return False
    return True


# ── X25519 
def x25519_generate() -> tuple[bytes, bytes]:
    """Returns (private_bytes, public_bytes)."""
    priv  = X25519PrivateKey.generate()
    priv_b = priv.private_bytes_raw()
    pub_b  = priv.public_key().public_bytes_raw()
    return priv_b, pub_b


def x25519_exchange(private_bytes: bytes, peer_public_bytes: bytes) -> bytes:
    priv = X25519PrivateKey.from_private_bytes(private_bytes)
    peer = X25519PublicKey.from_public_bytes(peer_public_bytes)
    return priv.exchange(peer)


# ── HKDF 
def hkdf_derive(
    ikm: bytes,
    length: int = 32,
    info: bytes = b"AITP-v1",
    salt: bytes | None = None,
) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(ikm)


# ── AES-256-GCM 
def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    aesgcm = AESGCM(key)
    nonce  = os.urandom(12)
    ct     = aesgcm.encrypt(nonce, plaintext, aad or None)
    return nonce + ct                           # prepend nonce


def aes_gcm_decrypt(key: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    aesgcm = AESGCM(key)
    nonce  = ciphertext[:12]
    ct     = ciphertext[12:]
    return aesgcm.decrypt(nonce, ct, aad or None)


# ── ML-KEM stub (post-quantum) 
try:
    from kyber_py.kyber import Kyber768          # type: ignore # pip install kyber-py
    _REAL_KEM = True
except ImportError:
    _REAL_KEM = False
    Kyber768 = None


@dataclass
class KEMKeyPair:
    public_key:  bytes
    private_key: bytes


def kem_generate() -> KEMKeyPair:
    if _REAL_KEM and Kyber768 is not None:
        pk, sk = Kyber768.keygen()
        return KEMKeyPair(pk, sk)
    # Stub — good enough for testing, replace with real impl in prod
    sk = os.urandom(32)
    pk = hashlib.sha3_256(sk + b"pk").digest() * 37   # 1184 bytes approx
    return KEMKeyPair(pk[:1184], sk)


def kem_encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """Returns (ciphertext, shared_secret)."""
    if _REAL_KEM and Kyber768 is not None and len(public_key) >= 1184:
        ct, ss = Kyber768.enc(public_key)
        return ct, ss
    ss = os.urandom(32)
    ct = hashlib.sha3_256(public_key[:32] + ss).digest() * 32  # stub ct
    return ct[:1088], ss


def kem_decapsulate(private_key: bytes, ciphertext: bytes) -> bytes:
    """Returns shared_secret."""
    if _REAL_KEM and Kyber768 is not None:
        return Kyber768.dec(private_key, ciphertext)
    return hashlib.sha3_256(private_key + ciphertext[:32]).digest()


# ── Session key derivation 
def derive_session_key(
    kem_shared:   bytes,
    x25519_shared: bytes,
) -> bytes:
    """Hybrid KEM — secure if either component is secure."""
    combined = bytes(a ^ b for a, b in zip(
        kem_shared[:32].ljust(32, b"\x00"),
        x25519_shared[:32].ljust(32, b"\x00"),
    ))
    return hkdf_derive(combined, info=b"AITP-v1-session")
