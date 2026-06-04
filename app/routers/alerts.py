from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from ..services.alerts import send_email_alert, build_scan_alert_html, trigger_scan_alert

router = APIRouter(prefix="/alerts", tags=["alerts"])


class TestAlertRequest(BaseModel):
    email: str
    threat_level: str = "CRITICAL"


class SubscribeRequest(BaseModel):
    email: str
    min_threat_level: str = "HIGH"
    webhook_url: Optional[str] = None


@router.post("/test")
async def send_test_alert(req: TestAlertRequest):
    """Send a test alert email"""
    mock_scan = {
        "input": "test-threat-actor.xyz",
        "scan_type": "domain",
        "threat_score": 87.5,
        "threat_level": req.threat_level,
        "entity_type": "BOT",
        "summary": "3 suspicious indicators found. High coordination with known bot network.",
        "signals": [
            {"name": "virustotal", "score": 85, "confidence": 0.95,
             "reasons": ["12/91 engines flagged as malicious", "Threat: Phishing.Generic"]},
            {"name": "domain", "score": 60, "confidence": 0.85,
             "reasons": ["Suspicious TLD: .xyz", "Domain age: 3 days — very new"]},
        ],
        "recommendations": [
            "Do not share personal information with this entity",
            "Report to platform trust & safety team",
            "VirusTotal flagged — avoid clicking any links",
        ]
    }

    html = build_scan_alert_html(mock_scan)
    result = await send_email_alert(
        to=[req.email],
        subject=f"🚨 ATIP Test Alert — {req.threat_level} Threat Detected",
        html=html,
    )

    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error", "Failed to send"))

    return {"message": f"Test alert sent to {req.email}", "email_id": result.get("email_id")}


@router.get("/config")
async def alert_config():
    """Get current alert configuration"""
    import os
    return {
        "resend_configured": bool(os.getenv("RESEND_API_KEY")),
        "default_recipients": os.getenv("ALERT_EMAILS", "").split(",") if os.getenv("ALERT_EMAILS") else [],
        "webhook_url": os.getenv("ALERT_WEBHOOK_URL", None),
        "min_threat_level": os.getenv("ALERT_MIN_LEVEL", "HIGH"),
        "triggers": [
            "scan_result HIGH or CRITICAL",
            "campaign threat level change to HIGH/CRITICAL",
            "evidence package exported",
        ]
    }
