import random


def generate_auth_token():
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    auth_token = "".join(random.choice(chars) for _ in range(32))
    return auth_token
