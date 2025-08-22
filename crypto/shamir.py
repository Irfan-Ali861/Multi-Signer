# crypto/shamir.py
from __future__ import annotations

import secrets
from functools import reduce
from typing import Iterable, List, Tuple, Optional

from .config import PRIME  # single source of truth


def _eval_poly(coeffs: List[int], x: int) -> int:
    """
    Evaluate polynomial a0 + a1*x + ... + a_{t-1}*x^{t-1} mod PRIME using Horner's method.
    coeffs[0] is the secret (constant term).
    """
    res = 0
    for a in reversed(coeffs):
        res = (res * x + a) % PRIME
    return res


def generate_shares(secret: int, n: int, t: int) -> List[Tuple[int, int]]:
    """
    Generate n Shamir shares with threshold t over F_p.
    Returns list of (x, y) with x = 1..n (distinct, non-zero).
    """
    if not (1 <= t <= n):
        raise ValueError("Require 1 <= t <= n.")
    if not (0 < secret < PRIME):
        raise ValueError("secret must be in 1..PRIME-1.")

    # Random coefficients: a0=secret, a1..a_{t-1} uniform in [1, PRIME-1]
    coeffs = [secret] + [secrets.randbelow(PRIME - 1) + 1 for _ in range(t - 1)]

    shares: List[Tuple[int, int]] = []
    for x in range(1, n + 1):
        y = _eval_poly(coeffs, x)
        shares.append((x, y))
    return shares


def _lagrange_interpolation_at_zero(x_s: List[int], y_s: List[int]) -> int:
    """
    Interpolate P(0) from points (x_i, y_i) with distinct, non-zero x_i in F_p:
      P(0) = sum_i y_i * ∏_{j≠i} (-x_j) * (x_i - x_j)^(-1)  mod p
    """
    def PI(vals: Iterable[int]) -> int:
        return reduce(lambda a, b: (a * b) % PRIME, vals, 1)

    if not x_s or not y_s or len(x_s) != len(y_s):
        raise ValueError("Invalid points for interpolation.")

    # x_i must be distinct and non-zero
    if any(x == 0 for x in x_s) or len(set(x_s)) != len(x_s):
        raise ValueError("x-coordinates must be distinct and non-zero.")

    result = 0
    for i, (xi, yi) in enumerate(zip(x_s, y_s)):
        denom = PI(((xi - xj) % PRIME) for j, xj in enumerate(x_s) if j != i)
        numer = PI(((-xj) % PRIME) for j, xj in enumerate(x_s) if j != i)
        inv_denom = pow(denom, PRIME - 2, PRIME)  # Fermat's little theorem (p is prime)
        li0 = (numer * inv_denom) % PRIME
        result = (result + yi * li0) % PRIME
    return result


def reconstruct_secret(
    shares: List[Tuple[int, int]],
    *,
    require_t: Optional[int] = None,
) -> int:
    """
    Reconstruct the secret from provided shares using Lagrange interpolation at x=0.
    If require_t is given, enforce len(shares) >= require_t.
    """
    if require_t is not None and len(shares) < require_t:
        raise ValueError(f"Need at least {require_t} shares; got {len(shares)}")

    if not shares:
        raise ValueError("No shares provided.")

    x_s, y_s = zip(*shares)
    return _lagrange_interpolation_at_zero(list(x_s), list(y_s))


if __name__ == "__main__":
    # Simple self-test
    secret = 123456789
    n, t = 5, 3
    shares = generate_shares(secret, n, t)
    rec = reconstruct_secret(shares[:t])
    print("Reconstructed OK:", rec == secret)
