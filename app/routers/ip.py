from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
import re

from ..services.ip_analysis import full_ip_analysis

router = APIRouter(prefix="/ip", tags=["ip"])


def is_valid_ip(ip: str) -> bool:
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    parts = ip.split('.')
    return all(0 <= int(p) <= 255 for p in parts)


def is_private_ip(ip: str) -> bool:
    parts = [int(p) for p in ip.split('.')]
    return (
        parts[0] == 10 or
        (parts[0] == 172 and 16 <= parts[1] <= 31) or
        (parts[0] == 192 and parts[1] == 168) or
        parts[0] == 127
    )


@router.get("/{ip}")
async def analyze_ip(ip: str):
    """
    Full IP intelligence analysis.
    Combines Shodan, VirusTotal, AbuseIPDB, and geolocation.
    """
    if not is_valid_ip(ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format")

    if is_private_ip(ip):
        raise HTTPException(status_code=400, detail="Private IP addresses cannot be analyzed")

    try:
        result = await full_ip_analysis(ip)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/batch")
async def analyze_ips_batch(body: dict):
    """Analyze multiple IPs at once (max 10)"""
    ips = body.get("ips", [])
    if not ips:
        raise HTTPException(status_code=400, detail="Provide list of IPs")
    if len(ips) > 10:
        raise HTTPException(status_code=400, detail="Max 10 IPs per batch")

    import asyncio
    valid_ips = [ip for ip in ips if is_valid_ip(ip) and not is_private_ip(ip)]
    if not valid_ips:
        raise HTTPException(status_code=400, detail="No valid public IPs provided")

    results = await asyncio.gather(*[full_ip_analysis(ip) for ip in valid_ips])
    return {
        "results": list(results),
        "total": len(results),
        "high_risk": [r["ip"] for r in results if r["threat_score"] >= 50],
    }
