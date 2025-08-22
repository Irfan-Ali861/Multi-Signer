# Threshold Schnorr: Off-chain Signing + On-chain Verification (Sepolia)

This project demonstrates **threshold Schnorr signatures**: a secret key is split using **Shamir’s Secret Sharing** (t-of-n), a valid Schnorr **signature is produced off-chain** in Python, and the signature is **verified on-chain** by a Solidity contract using the EIP-198 **modexp precompile**.

---

## Repository Layout

```
crypto/                     # Python crypto modules
  ├─ __init__.py
  ├─ config.py              # PRIME, GENERATOR (secp256k1 prime; g = 2)
  ├─ schnorr.py             # sign/verify (secrets-based nonces; deterministic option)
  ├─ shamir.py              # Shamir secret sharing (t-of-n)
  └─ threshold_schnorr.py   # reconstruct + threshold sign
contracts/
  └─ SchnorrVerifier.sol    # view-only verifier (modexp precompile)
scripts/
  ├─ sign_and_verify_demo.py # end-to-end demo (+ optional JSON artifact)
  └─ verify_on_chain.py      # verify from JSON or explicit args
abi/
  └─ contract_abi.json       # ABI of deployed verifier
config/
  └─ sepolia.json            # fallback config (rpc_url, contract_address, chain_id)
tests/
  ├─ test_shamir.py
  ├─ test_schnorr.py
  └─ test_schnorr_deterministic.py
output/                      # (generated) artifacts like run_fixed.json
```

---

## Prerequisites

- Python **3.9+** (tested on 3.9)
- Sepolia RPC endpoint (Infura/Alchemy)
- A deployed `SchnorrVerifier` contract on Sepolia

---

## Setup

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt   # or: pip install web3 python-dotenv pytest ipykernel
```

Create a **.env** at the project root (NOT committed):

```bash
# .env (example)
RPC_URL=https://sepolia.infura.io/v3/<YOUR_PROJECT_ID>
CONTRACT_ADDRESS=0x37dE7EC1F7E9E18203fE27683e48CC994b65c23C
CHAIN_ID=11155111
```

> Scripts load `.env` explicitly and fall back to `config/sepolia.json` if an env var is missing.

---

## Quickstart (End-to-End)

**Deterministic demo (new key each run; deterministic nonce with `--det`):**
```bash
python -m scripts.sign_and_verify_demo --det --message "Authorize multisig action" --n 5 --t 3
```

**Fully reproducible demo (fixed secret) and save artifacts:**
```bash
python -m scripts.sign_and_verify_demo --det --fixed-secret 123456789   --message "Authorize multisig action" --n 5 --t 3   --out output/run_fixed.json
```

**Verify on-chain from the saved JSON:**
```bash
python -m scripts.verify_on_chain --from-json output/run_fixed.json
```

Expected:
```
Connected: True
On-chain valid: True
```

---

## Tests

```bash
python -m pytest -q
```

You should see all tests passing.

---

## (Recommended) Context-Bound Messages

For replay resistance, bind signatures to your chain & contract and include a nonce/expiry. You can pass a context-bound message manually:

```
TSIGv1|chain=11155111|verifier=0xYOUR_CONTRACT|memo=Authorize multisig action|nonce=<hex>|exp=<unix_ts>
```

Example:
```bash
python -m scripts.sign_and_verify_demo --det --fixed-secret 123456789   --message "TSIGv1|chain=11155111|verifier=0x37dE7EC1F7E9E18203fE27683e48CC994b65c23C|memo=Authorize multisig action|nonce=abcdef1234|exp=1924992000"   --n 5 --t 3 --out output/run_ctx.json

python -m scripts.verify_on_chain --from-json output/run_ctx.json
```

*(Alternatively, make this wrapping the default inside `sign_and_verify_demo.py` before signing.)*

---

## Troubleshooting

- **401 Unauthorized / Connected: False**  
  Your `RPC_URL` is missing/invalid. Set it in `.env` or `config/sepolia.json`.

- **On-chain valid: False**  
  Ensure Python & Solidity use the **same PRIME/GENERATOR** and challenge `h = keccak(r || keccak(message))`. Check the **contract address** and **chain**.

- **LibreSSL warning on macOS**  
  Harmless (from `urllib3`). You can ignore it or switch to a Python build linked to OpenSSL for a clean console.

---

## Security & Secrets

- Keep RPC URLs/keys in **`.env`** (never commit secrets).
- Artifacts saved by `--out` do **not** include your RPC URL.
- Signatures use Python’s **`secrets`** for all randomness (keys, nonces).

---

## Repro Commands (copy-paste)

```bash
# Deterministic demo + save JSON
python -m scripts.sign_and_verify_demo --det --fixed-secret 123456789   --message "Authorize multisig action" --n 5 --t 3   --out output/run_fixed.json

# Verify from JSON (on-chain)
python -m scripts.verify_on_chain --from-json output/run_fixed.json

# Run tests
python -m pytest -q
```

---

## Appendices (optional helpers)

**`.gitignore`**
```gitignore
venv/
.env
__pycache__/
.pytest_cache/
*.egg-info/
dist/
build/
.DS_Store
*.swp
output/
*.log
.ipynb_checkpoints/
```

**`requirements.txt`**
```txt
web3>=6
python-dotenv>=1
pytest>=8
hypothesis>=6        # optional (property tests)
ipykernel
```

---
