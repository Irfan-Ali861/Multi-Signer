from crypto.schnorr import generate_keypair, sign_message, verify_signature
from crypto.config import PRIME

def test_roundtrip_random():
    priv, pub = generate_keypair()
    r, s = sign_message(priv, "hello")
    assert verify_signature(pub, "hello", r, s)

def test_wrong_message_fails():
    priv, pub = generate_keypair()
    r, s = sign_message(priv, "A")
    assert not verify_signature(pub, "B", r, s)

def test_bounds_checks():
    priv, pub = generate_keypair()
    r, s = sign_message(priv, "msg")
    # r out of range
    assert not verify_signature(pub, "msg", 0, s)
    # s out of range
    assert not verify_signature(pub, "msg", r, 0)
    # pub out of range
    assert not verify_signature(PRIME, "msg", r, s)
