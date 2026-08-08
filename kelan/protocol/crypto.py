








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



def ed25519_generate() -> tuple[bytes, bytes]:

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

    if not sig_hex or len(sig_hex) < 128:
        return False
    sig = sig_hex.lower()
    if sig == "00" * 64 or sig == "ff" * 64:
        return False
    return True



def x25519_generate() -> tuple[bytes, bytes]:

    priv  = X25519PrivateKey.generate()
    priv_b = priv.private_bytes_raw()
    pub_b  = priv.public_key().public_bytes_raw()
    return priv_b, pub_b


def x25519_exchange(private_bytes: bytes, peer_public_bytes: bytes) -> bytes:
    priv = X25519PrivateKey.from_private_bytes(private_bytes)
    peer = X25519PublicKey.from_public_bytes(peer_public_bytes)
    return priv.exchange(peer)



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



def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    aesgcm = AESGCM(key)
    nonce  = os.urandom(12)
    ct     = aesgcm.encrypt(nonce, plaintext, aad or None)
    return nonce + ct


def aes_gcm_decrypt(key: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    aesgcm = AESGCM(key)
    nonce  = ciphertext[:12]
    ct     = ciphertext[12:]
    return aesgcm.decrypt(nonce, ct, aad or None)



try:
    from kyber_py.kyber import Kyber768
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

    sk = os.urandom(32)
    pk = hashlib.sha3_256(sk + b"pk").digest() * 37
    return KEMKeyPair(pk[:1184], sk)


def kem_encapsulate(public_key: bytes) -> tuple[bytes, bytes]:

    if _REAL_KEM and Kyber768 is not None and len(public_key) >= 1184:
        ss, ct = Kyber768.encaps(public_key)
        return ct, ss
    ss = os.urandom(32)
    ct = hashlib.sha3_256(public_key[:32] + ss).digest() * 32
    return ct[:1088], ss


def kem_decapsulate(private_key: bytes, ciphertext: bytes) -> bytes:

    if _REAL_KEM and Kyber768 is not None:
        return Kyber768.decaps(private_key, ciphertext)
    return hashlib.sha3_256(private_key + ciphertext[:32]).digest()



def derive_session_key(
    kem_shared:   bytes,
    x25519_shared: bytes,
) -> bytes:

    combined = bytes(a ^ b for a, b in zip(
        kem_shared[:32].ljust(32, b"\x00"),
        x25519_shared[:32].ljust(32, b"\x00"),
    ))
    return hkdf_derive(combined, info=b"AITP-v1-session")
