import hashlib


def hash_password(password):
    # Weak cryptographic hash (MD5)
    return hashlib.md5(password.encode()).hexdigest()
