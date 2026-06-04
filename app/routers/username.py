from fastapi import APIRouter, HTTPException
from ..services.username_scan import scan_username, analyze_username_threat
from ..services.scanner import get_threat_level
from ..utils.db import save_scan_result
from datetime import datetime
import uuid

router = APIRouter(prefix="/username", tags=["username"])


@router.get("/{username}")
async def analyze_username(username: str):
    """
    Scan username across 25+ platforms.
    Detects cross-platform presence and bot-like patterns.
    """
    username = username.strip().lstrip("@")
    if not username:
        raise HTTPException(status_code=400, detail="Username cannot be empty")
    if len(username) > 50:
        raise HTTPException(status_code=400, detail="Username too long")

    try:
        import time
        start = time.time()

        scan_result = await scan_username(username)

        if scan_result.get("error"):
            raise HTTPException(status_code=400, detail=scan_result["error"])

        threat_score, confidence, reasons = analyze_username_threat(username, scan_result)
        threat_level = get_threat_level(threat_score)

        result = {
            "scan_id": str(uuid.uuid4()),
            "input": username,
            "scan_type": "username",
            "threat_score": threat_score,
            "threat_level": threat_level,
            "entity_type": "SYNTHETIC_PERSONA" if threat_score > 40 else "UNKNOWN",
            "signals": [{
                "name": "cross_platform",
                "score": threat_score,
                "confidence": confidence,
                "reasons": reasons,
                "raw_data": {
                    "total_found": scan_result["total_found"],
                    "platforms_by_category": scan_result["platforms_by_category"],
                    "found_platforms": [p["platform"] for p in scan_result["found_on"]],
                }
            }],
            "summary": (
                f"Username '@{username}' found on {scan_result['total_found']} out of "
                f"{scan_result['total_checked']} platforms. "
                f"High confidence: {scan_result.get('high_confidence_count', 0)} | "
                f"Note: some results are low confidence — verify manually."
            ),
            "username_intel": {
                "username": username,
                "total_found": scan_result["total_found"],
                "total_checked": scan_result["total_checked"],
                "found_on": scan_result["found_on"],
                "platforms_by_category": scan_result["platforms_by_category"],
            },
            "recommendations": _get_recommendations(threat_score, scan_result),
            "scanned_at": datetime.utcnow().isoformat(),
            "scan_duration_ms": int((time.time() - start) * 1000),
        }

        # Save to DB
        try:
            await save_scan_result(result)
        except Exception:
            pass

        return result

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def _get_recommendations(threat_score: float, scan_result: dict) -> list:
    recs = []
    found = scan_result.get("total_found", 0)
    found_on = [p["platform"] for p in scan_result.get("found_on", [])]

    if found == 0:
        recs.append("Username not found — may be a throwaway account or very new")
    elif threat_score >= 40:
        recs.append("Suspicious cross-platform pattern — investigate account creation dates")
        recs.append("Check if accounts were created simultaneously (coordinated persona)")
    else:
        recs.append(f"Profile found on {found} platforms — appears to be a real user")

    if "Twitter/X" in found_on or "Facebook" in found_on:
        recs.append("Check account creation date and posting history on social platforms")

    if "GitHub" in found_on or "GitLab" in found_on:
        recs.append("Developer profiles found — check commit history for authenticity")

    return recs
