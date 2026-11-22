import hashlib
import os


def safe_store_password(password: str):
    salt = os.urandom(16)
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
