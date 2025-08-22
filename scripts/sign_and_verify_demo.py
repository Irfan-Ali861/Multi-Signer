# scripts/sign_and_verify_demo.py
import argparse
import json
import os
import sys
import time
import secrets
from pathlib import Path
from typing import Dict, Any

from web3 import Web3

# Load .env explicitly from repo root if present
try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None

# Make project root importable
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Crypto modules
from crypto.config import PRIME, GENERATOR
from crypto.schnorr import generate_keypair, sign_message, verify_signature
from crypto.shamir import generate_shares
from crypto.threshold_schnorr import threshold_sign


def load_network() -> Dict[str, Any]:
    """Load network config from config/sepolia.json, then override with .env if present."""
    cfg_path = ROOT / "config" / "sepolia.json"
    with open(cfg_path, "r", encoding="utf-8") as fh:
        net = json.load(fh)

    # Load .env first so env vars are available
    if load_dotenv:
        try:
            load_dotenv(dotenv_path=ROOT / ".env", override=True)
        except Exception:
            pass

    # Allow env override; tolerate "env:RPC_URL" placeholder in JSON
    rpc = os.getenv("RPC_URL")
    if not rpc:
        rpc = net.get("rpc_url")
        if isinstance(rpc, str) and rpc.startswith("env:"):
            rpc = os.getenv("RPC_URL")

    addr = os.getenv("CONTRACT_ADDRESS") or net.get("contract_address")
    chain_id = os.getenv("CHAIN_ID") or net.get("chain_id", 11155111)

    return {
        "rpc_url": rpc,
        "contract_address": addr,
        "chain_id": int(chain_id),
    }


def get_contract(w3: Web3):
    """Instantiate the on-chain verifier from ABI + address."""
    abi_path = ROOT / "abi" / "contract_abi.json"
    with open(abi_path, "r", encoding="utf-8") as fh:
        abi = json.load(fh)

    net = load_network()
    if not net["contract_address"]:
        raise RuntimeError("Missing CONTRACT_ADDRESS (in .env or config/sepolia.json).")

    address = Web3.to_checksum_address(net["contract_address"])
    return w3.eth.contract(address=address, abi=abi)


def verify_on_chain(contract, pub_key: int, r: int, s: int, msg_hash_hex: str) -> bool:
    """Call the view verifier on-chain."""
    # msg_hash_hex like "0x...."
    if msg_hash_hex.startswith("0x"):
        msg_hash_hex = msg_hash_hex[2:]
    msg_hash_bytes32 = bytes.fromhex(msg_hash_hex)
    if len(msg_hash_bytes32) != 32:
        raise ValueError("msg_hash must be 32 bytes (keccak256).")
    return contract.functions.verifySignature(pub_key, r, s, msg_hash_bytes32).call()


def main():
    parser = argparse.ArgumentParser(description="Threshold Schnorr: sign off-chain and verify on-chain (Sepolia).")
    parser.add_argument("--det", action="store_true", help="Use deterministic nonces for reproducibility.")
    parser.add_argument("--fixed-secret", type=int, default=None, help="Use this fixed private key (int) for reproducible runs.")
    parser.add_argument("--message", type=str, required=True, help="Message to sign (plain text).")
    parser.add_argument("--n", type=int, default=5, help="Total number of shares.")
    parser.add_argument("--t", type=int, default=3, help="Threshold (min shares).")
    parser.add_argument("--out", type=str, default=None, help="If set, write JSON artifact here.")
    args = parser.parse_args()

    # Load network, web3, and contract
    net = load_network()
    w3 = Web3(Web3.HTTPProvider(net["rpc_url"])) if net["rpc_url"] else None
    connected = (w3 is not None) and w3.is_connected()
    print("Connected:", bool(connected))
    if not connected:
        # We still continue to show off-chain validity
        w3 = None
        contract = None
        chain_id = net["chain_id"]
    else:
        chain_id = w3.eth.chain_id
        contract = get_contract(w3)

    contract_address = net["contract_address"] or "0x0000000000000000000000000000000000000000"

    # Optional: bind context to prevent replay (auto-wrap unless already TSIGv1)
    msg = args.message
    if not msg.startswith("TSIGv1|"):
        nonce = secrets.token_hex(8)
        expiry = int(time.time()) + 15 * 60
        msg = (
            f"TSIGv1|chain={chain_id}|verifier={contract_address}|"
            f"memo={msg}|nonce={nonce}|exp={expiry}"
        )

    # Choose private key
    if args.fixed_secret is not None:
        priv = args.fixed_secret % PRIME
        if priv <= 0 or priv >= PRIME:
            raise ValueError("fixed-secret must be in [1, PRIME-1].")
        pub = pow(GENERATOR, priv, PRIME)
    else:
        priv, pub = generate_keypair()

    # Create shares and sign with threshold (t of n)
    shares = generate_shares(priv, args.n, args.t)
    r, s, msg_hash = threshold_sign(
        shares[: args.t], msg, deterministic=args.det, require_t=args.t  # use first t shares for demo
    )

    # Off-chain verification (Python)
    offchain_ok = verify_signature(pub, msg, r, s)
    print("Off-chain valid:", bool(offchain_ok))

    # On-chain verification (Solidity)
    onchain_ok = False
    if connected and contract is not None:
        onchain_ok = verify_on_chain(contract, pub, r, s, msg_hash.hex())
        print("On-chain valid:", bool(onchain_ok))
    else:
        print("On-chain valid: (skipped; not connected)")

    # Pretty print key values
    print("pub:", pub)
    print("r:", r)
    print("s:", s)
    print("msg_hash (hex):", msg_hash.hex())

    # Optional artifact
    if args.out:
        outp = Path(args.out)
        outp.parent.mkdir(parents=True, exist_ok=True)
        artifact = {
            "message": msg,
            "chain_id": chain_id,
            "contract_address": contract_address,
            "pub": str(pub),
            "r": str(r),
            "s": str(s),
            "msg_hash": "0x" + msg_hash.hex(),
        }
        with open(outp, "w", encoding="utf-8") as fh:
            json.dump(artifact, fh, indent=2)
        print(f"Wrote {outp}")


if __name__ == "__main__":
    main()
