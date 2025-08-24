# scripts/estimate_gas.py
import argparse, json, os, sys
from pathlib import Path
from web3 import Web3
try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))

def load_net():
    cfg = json.load(open(ROOT/"config"/"sepolia.json"))
    if load_dotenv:
        try: load_dotenv(dotenv_path=ROOT/".env", override=True)
        except Exception: pass
    rpc = os.getenv("RPC_URL") or cfg.get("rpc_url")
    if isinstance(rpc, str) and rpc.startswith("env:"): rpc = os.getenv("RPC_URL")
    addr = os.getenv("CONTRACT_ADDRESS") or cfg.get("contract_address")
    return rpc, Web3.to_checksum_address(addr), json.load(open(ROOT/"abi"/"contract_abi.json"))

def load_values(path: Path):
    data = json.load(open(path))
    pub = int(data["pub"]); r = int(data["r"]); s = int(data["s"])
    h  = bytes.fromhex(data["msg_hash"][2:] if data["msg_hash"].startswith("0x") else data["msg_hash"])
    if len(h)!=32: raise ValueError("msg_hash must be 32 bytes")
    return pub, r, s, h

def main():
    ap = argparse.ArgumentParser(description="Estimate gas for verifySignature")
    ap.add_argument("--from-json", required=True)
    a = ap.parse_args()
    rpc, addr, abi = load_net()
    w3 = Web3(Web3.HTTPProvider(rpc)); assert w3.is_connected(), "RPC not reachable"
    c = w3.eth.contract(address=addr, abi=abi)
    pub, r, s, h = load_values(Path(a.from_json))
    gas = c.functions.verifySignature(pub, r, s, h).estimate_gas({"from":"0x000000000000000000000000000000000000dEaD"})
    print("Estimated gas:", gas)

if __name__ == "__main__": main()
