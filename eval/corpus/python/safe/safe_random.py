import secrets


def generate_safe_auth_token():
    return secrets.token_hex(32)
