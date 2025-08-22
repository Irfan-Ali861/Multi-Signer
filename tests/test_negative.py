# tests/test_negative.py
from crypto.schnorr import generate_keypair, sign_message, verify_signature

def test_wrong_message_fails():
    priv, pub = generate_keypair()
    r, s = sign_message(priv, "A", deterministic=True)
    assert not verify_signature(pub, "B", r, s)

def test_bad_bounds_fail():
    priv, pub = generate_keypair()
    r, s = sign_message(priv, "msg", deterministic=True)
    assert not verify_signature(pub, "msg", 0, s)
    assert not verify_signature(pub, "msg", r, 0)
