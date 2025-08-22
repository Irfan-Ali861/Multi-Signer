# scripts/verify_on_chain.py
import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional

from web3 import Web3

# Load .env explicitly from repo root if present
try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def load_network() -> Dict[str, Any]:
    """Load network config from config/sepolia.json, then override with .env if present."""
    cfg_path = ROOT / "config" / "sepolia.json"
    with open(cfg_path, "r", encoding="utf-8") as fh:
        net = json.load(fh)

    if load_dotenv:
        try:
            load_dotenv(dotenv_path=ROOT / ".env", override=True)
        except Exception:
            pass

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
    abi_path = ROOT / "abi" / "contract_abi.json"
    with open(abi_path, "r", encoding="utf-8") as fh:
        abi = json.load(fh)

    net = load_network()
    if not net["contract_address"]:
        raise RuntimeError("Missing CONTRACT_ADDRESS (in .env or config/sepolia.json).")

    address = Web3.to_checksum_address(net["contract_address"])
    return w3.eth.contract(address=address, abi=abi)


def parse_args():
    p = argparse.ArgumentParser(description="Verify a Schnorr signature on-chain (view call).")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--from-json", type=str, help="Path to artifact JSON (from sign_and_verify_demo --out).")
    g.add_argument("--pub", type=int, help="Public key (uint256).")
    p.add_argument("--r", type=int, help="Signature r.")
    p.add_argument("--s", type=int, help="Signature s.")
    p.add_argument("--msg-hash", type=str, help="Keccak256(message) hex, e.g. 0x... (32 bytes).")
    return p.parse_args()


def load_values_from_json(path: Path):
    data = json.load(open(path, "r", encoding="utf-8"))
    pub = int(data["pub"])
    r = int(data["r"])
    s = int(data["s"])
    msg_hash_hex = data["msg_hash"]  # "0x..."
    return pub, r, s, msg_hash_hex


def to_bytes32(hexstr: str) -> bytes:
    if hexstr.startswith("0x"):
        hexstr = hexstr[2:]
    b = bytes.fromhex(hexstr)
    if len(b) != 32:
        raise ValueError("msg_hash must be 32 bytes (keccak256).")
    return b


def main():
    args = parse_args()

    # Connect
    net = load_network()
    w3 = Web3(Web3.HTTPProvider(net["rpc_url"])) if net["rpc_url"] else None
    connected = (w3 is not None) and w3.is_connected()
    print("Connected:", bool(connected))
    print("Chain:", net["chain_id"])
    if not connected:
        sys.exit(1)

    contract = get_contract(w3)

    # Load inputs
    if args.from_json:
        pub, r, s, msg_hash_hex = load_values_from_json(Path(args.from_json))
    else:
        if args.r is None or args.s is None or args.msg_hash is None:
            raise SystemExit("When not using --from-json, you must pass --pub, --r, --s, and --msg-hash.")
        pub, r, s = args.pub, args.r, args.s
        msg_hash_hex = args.msg_hash

    # Call contract
    ok = contract.functions.verifySignature(pub, r, s, to_bytes32(msg_hash_hex)).call()
    print("On-chain valid:", bool(ok))


if __name__ == "__main__":
    main()
