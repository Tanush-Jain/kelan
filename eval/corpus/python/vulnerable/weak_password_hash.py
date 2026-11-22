import hashlib


def store_user_password(password: str):
    # Weak password hash using fast MD5 without salt or work factor
    password_hash = hashlib.md5(password.encode()).hexdigest()
    return password_hash
