from kelan.protocol.crypto import ed25519_generate, ed25519_sign, ed25519_verify

def generate_keypair():
    # Returns (private_bytes, public_bytes)
    return ed25519_generate()

def sign(sk, msg):
    return ed25519_sign(sk, msg)

def verify(pk, msg, sig):
    return ed25519_verify(pk, sig, msg)
