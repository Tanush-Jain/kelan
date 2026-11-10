import hashlib


def safe_hash_password(password):
    # Strong cryptographic hash (SHA-256)
    return hashlib.sha256(password.encode()).hexdigest()
