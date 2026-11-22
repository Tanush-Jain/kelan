import hashlib


def safe_compute_hash(data):
    # Strong cryptographic hash (SHA-256)
    return hashlib.sha256(data.encode()).hexdigest()

