from web3 import Web3
from app.config import settings

ABI = [
 {"inputs":[{"internalType":"bytes32","name":"reportHash","type":"bytes32"}],
  "name":"registerReport","outputs":[],"stateMutability":"nonpayable","type":"function"},
 {"inputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],
  "name":"records","outputs":[{"internalType":"address","name":"registrar","type":"address"},
  {"internalType":"uint256","name":"timestamp","type":"uint256"},
  {"internalType":"bool","name":"exists","type":"bool"}],
  "stateMutability":"view","type":"function"}
]

def _client():
    if not settings.sepolia_rpc_url or not settings.report_registry_address:
        raise RuntimeError("Sepolia RPC URL and contract address must be configured.")
    w3 = Web3(Web3.HTTPProvider(settings.sepolia_rpc_url))
    if not w3.is_connected():
        raise RuntimeError("Could not connect to the configured RPC endpoint.")
    contract = w3.eth.contract(address=Web3.to_checksum_address(settings.report_registry_address), abi=ABI)
    return w3, contract

def register_report_hash(hash_hex: str) -> dict:
    if not settings.sepolia_private_key:
        raise RuntimeError("SEPOLIA_PRIVATE_KEY is not configured.")
    w3, contract = _client()
    account = w3.eth.account.from_key(settings.sepolia_private_key)
    digest = bytes.fromhex(hash_hex.removeprefix("0x"))
    fn = contract.functions.registerReport(digest)
    tx = fn.build_transaction({
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address),
        "chainId": settings.chain_id,
        "gas": 150000,
        "gasPrice": w3.eth.gas_price,
    })
    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
    if receipt.status != 1:
        raise RuntimeError("Blockchain transaction reverted.")
    return {"tx_hash": tx_hash.hex(), "block_number": receipt.blockNumber}

def verify_report_hash(hash_hex: str) -> dict:
    w3, contract = _client()
    digest = bytes.fromhex(hash_hex.removeprefix("0x"))
    registrar, timestamp, exists = contract.functions.records(digest).call()
    return {"exists": exists, "registrar": registrar,
            "timestamp": timestamp, "hash_matches": bool(exists)}
