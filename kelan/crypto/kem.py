from kelan.protocol.crypto import kem_generate, kem_encapsulate, kem_decapsulate

def mlkem_keygen():
    pair = kem_generate()
    return pair.public_key, pair.private_key

def mlkem_encap(pk):
    return kem_encapsulate(pk)

def mlkem_decap(sk, ct):
    return kem_decapsulate(sk, ct)
