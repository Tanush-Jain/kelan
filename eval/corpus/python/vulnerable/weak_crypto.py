import hashlib


def compute_checksum(data):
    # Weak cryptographic hash (MD5)
    return hashlib.md5(data.encode()).hexdigest()

