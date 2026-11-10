"""Deploy with: python scripts/deploy_contract.py
Compile ABI/bytecode first using solc:
  solc --combined-json abi,bin contracts/ReportRegistry.sol > build.json
This script reads build.json generated from the exact Solidity source.
"""
import json, os
from pathlib import Path
from web3 import Web3
from dotenv import load_dotenv

load_dotenv()
rpc = os.getenv("SEPOLIA_RPC_URL")
key = os.getenv("SEPOLIA_PRIVATE_KEY")
if not rpc or not key:
    raise SystemExit("Set SEPOLIA_RPC_URL and SEPOLIA_PRIVATE_KEY in .env")
w3 = Web3(Web3.HTTPProvider(rpc))
if not w3.is_connected(): raise SystemExit("RPC connection failed")
build = json.loads(Path("build.json").read_text())
entry = next(v for k,v in build["contracts"].items() if k.endswith(":ReportRegistry"))
abi, bytecode = entry["abi"], entry["bin"]
account = w3.eth.account.from_key(key)
factory = w3.eth.contract(abi=abi, bytecode=bytecode)
tx = factory.constructor().build_transaction({
    "from": account.address, "nonce": w3.eth.get_transaction_count(account.address),
    "chainId": 11155111, "gas": 1500000, "gasPrice": w3.eth.gas_price
})
signed = account.sign_transaction(tx)
tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
if receipt.status != 1: raise SystemExit("Deployment reverted")
print("CONTRACT_ADDRESS=", receipt.contractAddress)
print("DEPLOY_TX=", tx_hash.hex())
print("BLOCK=", receipt.blockNumber)
