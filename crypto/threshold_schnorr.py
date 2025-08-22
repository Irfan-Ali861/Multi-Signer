# crypto/threshold_schnorr.py
from __future__ import annotations

from typing import List, Tuple, Optional

from .config import PRIME, GENERATOR
from .shamir import reconstruct_secret
from .schnorr import sign_message, keccak_challenge


def threshold_sign(
    shares: List[Tuple[int, int]],
    message: str,
    *,
    deterministic: bool = False,
    require_t: Optional[int] = None,
) -> Tuple[int, int, bytes]:
    """
    Reconstruct the secret from `shares` and produce (r, s, msg_hash).
    - deterministic=True makes the signature repeatable for the same (secret, message).
    - require_t: if provided, enforce a minimum number of shares.
    """
    if require_t is not None and len(shares) < require_t:
        raise ValueError(f"Need at least {require_t} shares; got {len(shares)}")

    priv = reconstruct_secret(shares)
    if not (0 < priv < PRIME):
        raise ValueError("Reconstructed secret out of range.")

    r, s = sign_message(priv, message, deterministic=deterministic)
    # bytes32 Keccak(message), consistent with Solidity
    _, msg_hash = keccak_challenge(r, message)
    return r, s, msg_hash


def pubkey_from_secret(secret: int) -> int:
    """Compute integer public key g^secret mod p."""
    if not (0 < secret < PRIME):
        raise ValueError("secret must be in 1..PRIME-1.")
    return pow(GENERATOR, secret, PRIME)


if __name__ == "__main__":
    # Self-test (run from project root: `python -m crypto.threshold_schnorr`)
    from .shamir import generate_shares
    from .schnorr import verify_signature

    secret = 123456789
    n, t = 5, 3
    msg = "Authorize multisig action"

    shares = generate_shares(secret, n, t)
    r, s, msg_hash = threshold_sign(shares[:t], msg, deterministic=True, require_t=t)
    pub = pubkey_from_secret(secret)

    print("Off-chain verify:", verify_signature(pub, msg, r, s))
    print("msg_hash (hex):", msg_hash.hex())
