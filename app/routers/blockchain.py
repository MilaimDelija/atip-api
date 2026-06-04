from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from ..services.blockchain import anchor_hash, verify_hash_on_chain, get_wallet_balance, compute_evidence_hash

router = APIRouter(prefix="/blockchain", tags=["blockchain"])


class AnchorRequest(BaseModel):
    data_hash: str
    campaign_id: Optional[str] = None
    evidence_type: str = "evidence"


class VerifyRequest(BaseModel):
    transaction_hash: str


@router.post("/anchor")
async def anchor_evidence(req: AnchorRequest):
    """Anchor evidence hash to Polygon Amoy blockchain"""
    if not req.data_hash or len(req.data_hash) != 64:
        raise HTTPException(status_code=400, detail="Invalid SHA-256 hash (must be 64 hex chars)")

    result = await anchor_hash(
        req.data_hash,
        {"type": req.evidence_type, "campaign_id": req.campaign_id or "none"}
    )

    if not result["success"] and result.get("error"):
        if "not configured" in str(result.get("error", "")):
            raise HTTPException(status_code=503, detail="Blockchain not configured")

    return result


@router.get("/verify/{tx_hash}")
async def verify_transaction(tx_hash: str):
    """Verify evidence hash exists on blockchain"""
    if not tx_hash.startswith("0x") or len(tx_hash) != 66:
        raise HTTPException(status_code=400, detail="Invalid transaction hash")

    result = await verify_hash_on_chain(tx_hash)
    return result


@router.get("/wallet")
async def wallet_info():
    """Get ATIP wallet balance and info"""
    return await get_wallet_balance()


@router.get("/status")
async def blockchain_status():
    """Check blockchain connection status"""
    try:
        from web3 import Web3
        w3 = Web3(Web3.HTTPProvider("https://rpc-amoy.polygon.technology"))
        connected = w3.is_connected()
        block = w3.eth.block_number if connected else None
        return {
            "connected": connected,
            "network": "Polygon Amoy Testnet",
            "chain_id": 80002,
            "latest_block": block,
            "wallet_configured": bool(__import__("os").getenv("BLOCKCHAIN_PRIVATE_KEY")),
            "explorer": "https://amoy.polygonscan.com",
        }
    except Exception as e:
        return {"connected": False, "error": str(e)}
