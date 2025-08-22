# crypto/schnorr.py
from __future__ import annotations

import secrets
from typing import Tuple
from web3 import Web3

from .config import PRIME, GENERATOR


def keccak_message(message: str) -> bytes:
    """
    Ethereum-compatible message hash (bytes32).
    """
    return Web3.keccak(text=message)


def keccak_challenge(r: int, message: str) -> Tuple[int, bytes]:
    """
    Computes Schnorr challenge:
      msg_hash = keccak(message)
      h        = keccak( r || msg_hash )  mod PRIME
    Returns (h, msg_hash).
    """
    if not (0 < r < PRIME):
        raise ValueError("r must be in range 1..PRIME-1")

    msg_hash = keccak_message(message)  # bytes32
    r_bytes = r.to_bytes(32, "big")
    h_bytes = Web3.keccak(r_bytes + msg_hash)
    h = int.from_bytes(h_bytes, "big") % PRIME
    return h, msg_hash


def _det_k(priv: int, msg_hash: bytes) -> int:
    """
    Deterministic nonce (for tests/demos).
    NOT RFC6979, but good enough for reproducibility in this prototype.
    """
    seed = Web3.keccak(priv.to_bytes(32, "big") + msg_hash)
    return (int.from_bytes(seed, "big") % (PRIME - 2)) + 1  # in [1, PRIME-2]


def generate_keypair() -> Tuple[int, int]:
    """
    Secure key generation using secrets.
    Returns (priv, pub) with pub = g^priv mod PRIME.
    """
    priv = secrets.randbelow(PRIME - 2) + 1  # in [1, PRIME-2]
    pub = pow(GENERATOR, priv, PRIME)
    return priv, pub


def sign_message(priv: int, message: str, *, deterministic: bool = False) -> Tuple[int, int]:
    """
    Schnorr-like signing in multiplicative group mod PRIME.

    s = (k + h*priv) mod (PRIME-1)
    where h = keccak(r || keccak(message)) mod PRIME and r = g^k mod PRIME.

    deterministic=True makes k reproducible for testing (do NOT use in production).
    """
    if not (0 < priv < PRIME):
        raise ValueError("priv must be in range 1..PRIME-1")

    # Precompute msg_hash for optional deterministic k
    _h_tmp, msg_hash = keccak_challenge(1, message)  # cheap way to get msg_hash only

    k = _det_k(priv, msg_hash) if deterministic else (secrets.randbelow(PRIME - 2) + 1)
    r = pow(GENERATOR, k, PRIME)

    h, _ = keccak_challenge(r, message)
    s = (k + h * priv) % (PRIME - 1)  # exponent group order for g in F_p^*
    return r, s


def verify_signature(pub: int, message: str, r: int, s: int) -> bool:
    """
    Verifies Schnorr-like signature:
      Check: g^s == r * pub^h  (mod PRIME), with h as defined above.
    """
    # Basic input sanity
    if not (0 < pub < PRIME):
        return False
    if not (0 < r < PRIME):
        return False
    if not (0 < s < (PRIME - 1)):
        return False

    h, _ = keccak_challenge(r, message)
    left = pow(GENERATOR, s, PRIME)
    right = (r * pow(pub, h, PRIME)) % PRIME
    return left == right


if __name__ == "__main__":
    # Minimal self-test (run from project root: `python -m crypto.schnorr`)
    print("schnorr module OK. PRIME =", hex(PRIME), "GEN =", GENERATOR)

    priv, pub = generate_keypair()
    msg = "sanity check"

    # Use deterministic mode for a repeatable console demo
    r, s = sign_message(priv, msg, deterministic=True)
    ok = verify_signature(pub, msg, r, s)
    print("Self-test verify:", ok)
    if not ok:
        raise SystemExit("Self-test failed")
