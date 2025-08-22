# tests/test_shamir.py
import pytest
from itertools import combinations

from crypto.shamir import generate_shares, reconstruct_secret
from crypto.config import PRIME


def test_generate_and_reconstruct_exact_t():
    secret, n, t = 123456789, 5, 3
    shares = generate_shares(secret, n, t)
    rec = reconstruct_secret(shares[:t])
    assert rec == secret


def test_all_t_subsets_reconstruct():
    secret, n, t = 987654321, 6, 3
    shares = generate_shares(secret, n, t)
    for subset in combinations(shares, t):
        assert reconstruct_secret(list(subset)) == secret


def test_using_all_shares_also_reconstructs():
    secret, n, t = 42, 5, 3
    shares = generate_shares(secret, n, t)
    assert reconstruct_secret(shares) == secret


def test_require_t_enforced():
    secret, n, t = 55555, 5, 4
    shares = generate_shares(secret, n, t)
    with pytest.raises(ValueError):
        reconstruct_secret(shares[:t - 1], require_t=t)


def test_duplicate_x_rejected():
    secret, n, t = 1010101, 5, 3
    shares = generate_shares(secret, n, t)
    dup = list(shares[:t])
    # Force a duplicate x-coordinate
    dup[1] = (dup[0][0], dup[1][1])
    with pytest.raises(ValueError):
        reconstruct_secret(dup)


def test_secret_bounds_in_generate_shares():
    with pytest.raises(ValueError):
        generate_shares(0, 5, 3)
    with pytest.raises(ValueError):
        generate_shares(PRIME, 5, 3)  # must be < PRIME


def test_threshold_params_validation():
    with pytest.raises(ValueError):
        generate_shares(123456, n=3, t=0)
    with pytest.raises(ValueError):
        generate_shares(123456, n=3, t=4)  # t > n
