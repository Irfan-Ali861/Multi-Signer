from crypto.schnorr import generate_keypair, sign_message, verify_signature

def test_deterministic_same_output():
    priv, pub = generate_keypair()
    msg = "repeatable"
    r1, s1 = sign_message(priv, msg, deterministic=True)
    r2, s2 = sign_message(priv, msg, deterministic=True)
    assert (r1, s1) == (r2, s2)
    assert verify_signature(pub, msg, r1, s1)

def test_random_differs_most_of_the_time():
    priv, pub = generate_keypair()
    msg = "random"
    r1, s1 = sign_message(priv, msg)
    r2, s2 = sign_message(priv, msg)
    assert (r1, s1) != (r2, s2)  # overwhelmingly likely
    assert verify_signature(pub, msg, r1, s1)
    assert verify_signature(pub, msg, r2, s2)
