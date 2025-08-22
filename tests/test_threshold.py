from crypto.shamir import generate_shares
from crypto.threshold_schnorr import threshold_sign, pubkey_from_secret
from crypto.schnorr import verify_signature

def test_threshold_roundtrip():
    secret = 123456789
    n, t = 5, 3
    shares = generate_shares(secret, n, t)
    msg = "Authorize multisig action"
    r, s, _ = threshold_sign(shares[:t], msg, deterministic=True, require_t=t)
    pub = pubkey_from_secret(secret)
    assert verify_signature(pub, msg, r, s)

def test_less_than_threshold_raises():
    secret = 987654321
    n, t = 5, 3
    shares = generate_shares(secret, n, t)
    try:
        threshold_sign(shares[:t-1], "M", deterministic=True, require_t=t)
        assert False, "Expected ValueError when shares < t"
    except ValueError:
        assert True
