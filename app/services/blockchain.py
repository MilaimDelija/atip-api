import os
import hashlib
import json
from typing import Dict, Optional
from datetime import datetime, timezone

# Polygon Amoy Testnet
POLYGON_AMOY_RPC = "https://rpc-amoy.polygon.technology"
CHAIN_ID = 80002  # Polygon Amoy

BLOCKCHAIN_PRIVATE_KEY = os.getenv("BLOCKCHAIN_PRIVATE_KEY", "")
BLOCKCHAIN_ADDRESS = os.getenv("BLOCKCHAIN_ADDRESS", "")


def get_web3():
    """Get Web3 instance connected to Polygon Amoy"""
    from web3 import Web3
    w3 = Web3(Web3.HTTPProvider(POLYGON_AMOY_RPC))
    return w3


async def anchor_hash(data_hash: str, metadata: Dict) -> Dict:
    """
    Anchor a SHA-256 hash to Polygon Amoy blockchain.
    Returns transaction details.
    """
    result = {
        "success": False,
        "transaction_hash": None,
        "block_number": None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data_hash": data_hash,
        "network": "Polygon Amoy Testnet",
        "explorer_url": None,
        "error": None,
    }

    if not BLOCKCHAIN_PRIVATE_KEY:
        result["error"] = "Blockchain not configured — set BLOCKCHAIN_PRIVATE_KEY"
        return result

    try:
        from web3 import Web3
        from eth_account import Account

        w3 = get_web3()

        if not w3.is_connected():
            result["error"] = "Cannot connect to Polygon Amoy"
            return result

        account = Account.from_key(BLOCKCHAIN_PRIVATE_KEY)

        # Encode hash as hex data for transaction
        # Format: ATIP:v1:{hash}:{type}:{timestamp}
        anchor_data = f"ATIP:v1:{data_hash}:{metadata.get('type', 'evidence')}:{metadata.get('campaign_id', 'none')}"
        encoded_data = ("0x" + anchor_data.encode().hex())[:500]

        # Get nonce
        nonce = w3.eth.get_transaction_count(account.address)

        # Build transaction — send 0 MATIC to self with data
        tx = {
            "nonce": nonce,
            "to": account.address,
            "value": 0,
            "gas": 50000,
            "gasPrice": w3.eth.gas_price,
            "data": encoded_data,
            "chainId": CHAIN_ID,
        }

        # Sign and send
        signed = account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
        tx_hex = tx_hash.hex()

        # Wait for receipt
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)

        result["success"] = receipt.status == 1
        result["transaction_hash"] = tx_hex
        result["block_number"] = receipt.blockNumber
        result["explorer_url"] = f"https://amoy.polygonscan.com/tx/{tx_hex}"
        result["gas_used"] = receipt.gasUsed

    except Exception as e:
        result["error"] = str(e)

    return result


async def verify_hash_on_chain(tx_hash: str) -> Dict:
    """Verify that a hash exists on chain by checking transaction"""
    result = {
        "verified": False,
        "transaction_hash": tx_hash,
        "block_number": None,
        "timestamp": None,
        "data": None,
        "error": None,
    }

    try:
        from web3 import Web3
        w3 = get_web3()

        tx = w3.eth.get_transaction(tx_hash)
        receipt = w3.eth.get_transaction_receipt(tx_hash)
        block = w3.eth.get_block(tx.blockNumber)

        result["verified"] = receipt.status == 1
        result["block_number"] = tx.blockNumber
        result["timestamp"] = datetime.fromtimestamp(
            block.timestamp, tz=timezone.utc
        ).isoformat()

        # Decode data
        if tx.input and tx.input != "0x":
            try:
                raw = bytes.fromhex(tx.input[2:])
                result["data"] = raw.decode("utf-8", errors="ignore")
            except Exception:
                result["data"] = tx.input

    except Exception as e:
        result["error"] = str(e)

    return result


def compute_evidence_hash(evidence_data: Dict) -> str:
    """Compute SHA-256 hash of evidence package"""
    canonical = json.dumps(evidence_data, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


async def get_wallet_balance() -> Dict:
    """Get ATIP wallet balance"""
    try:
        from web3 import Web3
        w3 = get_web3()
        if not BLOCKCHAIN_ADDRESS:
            return {"error": "No wallet configured"}
        balance_wei = w3.eth.get_balance(BLOCKCHAIN_ADDRESS)
        balance_matic = w3.from_wei(balance_wei, "ether")
        return {
            "address": BLOCKCHAIN_ADDRESS,
            "balance_matic": float(balance_matic),
            "balance_wei": balance_wei,
            "network": "Polygon Amoy Testnet",
            "explorer_url": f"https://amoy.polygonscan.com/address/{BLOCKCHAIN_ADDRESS}",
        }
    except Exception as e:
        return {"error": str(e)}
