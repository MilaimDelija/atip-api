import os
import httpx
import asyncio
from typing import Dict, List, Optional
from datetime import datetime, timezone

RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
FROM_EMAIL = "ATIP Alerts <onboarding@resend.dev>"

THREAT_COLORS = {
    "LOW": "#2dd4a0",
    "MEDIUM": "#f0a030",
    "HIGH": "#e8442a",
    "CRITICAL": "#ff1a1a",
}

THREAT_EMOJIS = {
    "LOW": "🟢",
    "MEDIUM": "🟡",
    "HIGH": "🔴",
    "CRITICAL": "🚨",
}


def build_scan_alert_html(scan_result: Dict) -> str:
    level = scan_result.get("threat_level", "UNKNOWN")
    color = THREAT_COLORS.get(level, "#666")
    emoji = THREAT_EMOJIS.get(level, "⚠️")
    score = scan_result.get("threat_score", 0)
    entity = scan_result.get("input", "Unknown")
    scan_type = scan_result.get("scan_type", "unknown").upper()
    summary = scan_result.get("summary", "")
    recommendations = scan_result.get("recommendations", [])

    signals_html = ""
    for sig in scan_result.get("signals", [])[:4]:
        sig_score = sig.get("score", 0)
        sig_color = "#e8442a" if sig_score > 60 else "#f0a030" if sig_score > 30 else "#2dd4a0"
        reasons = [r for r in sig.get("reasons", []) if "No significant" not in r and "appears" not in r][:2]
        reasons_html = "".join(f"<li style='color:#9ca3af;font-size:12px;margin:2px 0'>{r}</li>" for r in reasons)
        signals_html += f"""
        <tr>
          <td style='padding:8px 12px;border-bottom:1px solid #1a1e28;color:#e2e4ec;font-family:monospace;font-size:12px'>{sig['name'].upper()}</td>
          <td style='padding:8px 12px;border-bottom:1px solid #1a1e28;color:{sig_color};font-weight:bold;font-size:14px'>{int(sig_score)}</td>
          <td style='padding:8px 12px;border-bottom:1px solid #1a1e28'><ul style='margin:0;padding-left:16px'>{reasons_html}</ul></td>
        </tr>"""

    recs_html = "".join(f"<li style='margin:4px 0;color:#9ca3af;font-size:13px'>{r}</li>" for r in recommendations[:3])

    return f"""
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style='margin:0;padding:0;background:#060709;font-family:DM Sans,sans-serif'>
  <div style='max-width:600px;margin:0 auto;padding:32px 24px'>

    <!-- Header -->
    <div style='margin-bottom:24px'>
      <div style='display:inline-block;background:#0d0f14;border:1px solid #1a1e28;border-radius:4px;padding:4px 12px;margin-bottom:16px'>
        <span style='font-family:monospace;font-size:10px;color:#e8442a;letter-spacing:2px'>ATIP — THREAT ALERT</span>
      </div>
      <h1 style='margin:0;color:#e2e4ec;font-size:28px;font-weight:800;letter-spacing:-1px'>
        {emoji} {level} Threat Detected
      </h1>
    </div>

    <!-- Score card -->
    <div style='background:#0d0f14;border:1px solid {color}40;border-left:4px solid {color};border-radius:8px;padding:20px 24px;margin-bottom:16px'>
      <div style='font-family:monospace;font-size:10px;color:#6b7280;letter-spacing:2px;text-transform:uppercase;margin-bottom:8px'>
        {scan_type} ANALYSIS
      </div>
      <div style='font-size:48px;font-weight:800;color:{color};line-height:1;margin-bottom:8px'>{int(score)}<span style='font-size:18px;color:#6b7280'>/100</span></div>
      <div style='font-family:monospace;font-size:13px;color:#e2e4ec;margin-bottom:4px'>{entity}</div>
      <div style='font-size:13px;color:#9ca3af;line-height:1.6'>{summary}</div>
    </div>

    <!-- Signals -->
    <div style='background:#0d0f14;border:1px solid #1a1e28;border-radius:8px;overflow:hidden;margin-bottom:16px'>
      <div style='padding:12px 16px;border-bottom:1px solid #1a1e28'>
        <span style='font-family:monospace;font-size:10px;color:#6b7280;letter-spacing:2px;text-transform:uppercase'>Detection Signals</span>
      </div>
      <table style='width:100%;border-collapse:collapse'>
        <thead>
          <tr style='background:#13161e'>
            <th style='padding:8px 12px;text-align:left;font-family:monospace;font-size:9px;color:#6b7280;letter-spacing:1px'>SIGNAL</th>
            <th style='padding:8px 12px;text-align:left;font-family:monospace;font-size:9px;color:#6b7280;letter-spacing:1px'>SCORE</th>
            <th style='padding:8px 12px;text-align:left;font-family:monospace;font-size:9px;color:#6b7280;letter-spacing:1px'>EVIDENCE</th>
          </tr>
        </thead>
        <tbody>{signals_html}</tbody>
      </table>
    </div>

    <!-- Recommendations -->
    {f'''<div style='background:#0d0f14;border:1px solid #1a1e28;border-radius:8px;padding:16px 20px;margin-bottom:16px'>
      <div style='font-family:monospace;font-size:10px;color:#6b7280;letter-spacing:2px;text-transform:uppercase;margin-bottom:10px'>Recommendations</div>
      <ul style='margin:0;padding-left:16px'>{recs_html}</ul>
    </div>''' if recommendations else ''}

    <!-- Footer -->
    <div style='text-align:center;padding-top:16px;border-top:1px solid #1a1e28'>
      <a href='https://atip-snowy.vercel.app' style='display:inline-block;background:#e8442a;color:#fff;padding:10px 24px;border-radius:6px;text-decoration:none;font-size:13px;font-weight:700;margin-bottom:12px'>
        Open ATIP Platform →
      </a>
      <div style='font-family:monospace;font-size:10px;color:#4a5068'>
        ATIP — Agentic Threat Intelligence Platform<br>
        Neuronium Engineers · Frankfurt am Main
      </div>
    </div>

  </div>
</body>
</html>"""


def build_campaign_alert_html(campaign: Dict, event_type: str) -> str:
    level = campaign.get("threat_level", "UNKNOWN")
    color = THREAT_COLORS.get(level, "#666")
    emoji = THREAT_EMOJIS.get(level, "⚠️")
    name = campaign.get("name", "Unknown Campaign")
    target = campaign.get("target", "")
    coord = campaign.get("coordination_score", 0)
    entities = campaign.get("entity_count", 0)
    tactics = campaign.get("tactics", [])

    tactics_html = "".join(
        f"<span style='display:inline-block;background:#1a1e28;color:#f0a030;font-family:monospace;font-size:10px;padding:3px 8px;border-radius:20px;margin:2px'>{t}</span>"
        for t in tactics[:4]
    )

    event_labels = {
        "THREAT_LEVEL_CHANGE": "⚡ Threat Level Changed",
        "ENTITY_ADDED": "➕ New Entity Detected",
        "EVIDENCE_EXPORTED": "📋 Evidence Package Generated",
        "CAMPAIGN_CREATED": "🆕 New Campaign Created",
    }
    event_label = event_labels.get(event_type, f"📌 {event_type}")

    return f"""
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style='margin:0;padding:0;background:#060709;font-family:DM Sans,sans-serif'>
  <div style='max-width:600px;margin:0 auto;padding:32px 24px'>
    <div style='margin-bottom:24px'>
      <div style='display:inline-block;background:#0d0f14;border:1px solid #1a1e28;border-radius:4px;padding:4px 12px;margin-bottom:16px'>
        <span style='font-family:monospace;font-size:10px;color:#e8442a;letter-spacing:2px'>ATIP — CAMPAIGN ALERT</span>
      </div>
      <h1 style='margin:0;color:#e2e4ec;font-size:24px;font-weight:800'>{event_label}</h1>
    </div>

    <div style='background:#0d0f14;border:1px solid {color}40;border-left:4px solid {color};border-radius:8px;padding:20px 24px;margin-bottom:16px'>
      <div style='font-size:20px;font-weight:800;color:#e2e4ec;margin-bottom:4px'>{name}</div>
      {f"<div style='font-family:monospace;font-size:11px;color:#e8442a;margin-bottom:12px'>Target: {target}</div>" if target else ""}
      <div style='display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-top:16px'>
        <div>
          <div style='font-family:monospace;font-size:9px;color:#6b7280;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px'>Threat</div>
          <div style='font-size:18px;font-weight:800;color:{color}'>{emoji} {level}</div>
        </div>
        <div>
          <div style='font-family:monospace;font-size:9px;color:#6b7280;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px'>Coordination</div>
          <div style='font-size:18px;font-weight:800;color:#f0a030'>{int(coord*100)}%</div>
        </div>
        <div>
          <div style='font-family:monospace;font-size:9px;color:#6b7280;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px'>Entities</div>
          <div style='font-size:18px;font-weight:800;color:#4a9eff'>{entities}</div>
        </div>
      </div>
      {f"<div style='margin-top:16px'>{tactics_html}</div>" if tactics else ""}
    </div>

    <div style='text-align:center;padding-top:16px;border-top:1px solid #1a1e28'>
      <a href='https://atip-snowy.vercel.app/campaigns' style='display:inline-block;background:#e8442a;color:#fff;padding:10px 24px;border-radius:6px;text-decoration:none;font-size:13px;font-weight:700;margin-bottom:12px'>
        View Campaign →
      </a>
      <div style='font-family:monospace;font-size:10px;color:#4a5068'>
        ATIP — Agentic Threat Intelligence Platform · Neuronium Engineers
      </div>
    </div>
  </div>
</body>
</html>"""


async def send_email_alert(
    to: List[str],
    subject: str,
    html: str,
) -> Dict:
    key = os.getenv("RESEND_API_KEY", RESEND_API_KEY)
    if not key:
        return {"success": False, "error": "RESEND_API_KEY not configured"}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json={"from": FROM_EMAIL, "to": to, "subject": subject, "html": html},
            )
            data = resp.json()
            return {
                "success": resp.status_code == 200,
                "email_id": data.get("id"),
                "error": data.get("message") if resp.status_code != 200 else None,
            }
    except Exception as e:
        return {"success": False, "error": str(e)}


async def send_webhook_alert(webhook_url: str, payload: Dict) -> Dict:
    """Send alert to webhook URL (Slack, Discord, custom)"""
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(
                webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            return {"success": resp.status_code < 300, "status": resp.status_code}
    except Exception as e:
        return {"success": False, "error": str(e)}


async def trigger_scan_alert(scan_result: Dict, alert_emails: List[str], webhook_url: Optional[str] = None):
    """Trigger alert for high/critical scan results"""
    level = scan_result.get("threat_level", "LOW")
    if level not in ("HIGH", "CRITICAL"):
        return

    entity = scan_result.get("input", "Unknown")
    emoji = THREAT_EMOJIS.get(level, "⚠️")
    subject = f"{emoji} ATIP {level} Alert — {entity[:50]}"
    html = build_scan_alert_html(scan_result)

    tasks = []
    if alert_emails:
        tasks.append(send_email_alert(alert_emails, subject, html))

    if webhook_url:
        payload = {
            "text": f"{emoji} *ATIP {level} Alert*: `{entity}` — Score: {scan_result.get('threat_score', 0)}/100",
            "atip_data": {
                "threat_level": level,
                "threat_score": scan_result.get("threat_score"),
                "entity": entity,
                "summary": scan_result.get("summary"),
            }
        }
        tasks.append(send_webhook_alert(webhook_url, payload))

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


async def trigger_campaign_alert(
    campaign: Dict,
    event_type: str,
    alert_emails: List[str],
    webhook_url: Optional[str] = None
):
    """Trigger alert for campaign events"""
    level = campaign.get("threat_level", "LOW")
    if level not in ("HIGH", "CRITICAL") and event_type not in ("THREAT_LEVEL_CHANGE", "EVIDENCE_EXPORTED"):
        return

    name = campaign.get("name", "Unknown")
    emoji = THREAT_EMOJIS.get(level, "⚠️")
    subject = f"{emoji} ATIP Campaign Alert — {name[:50]} [{event_type}]"
    html = build_campaign_alert_html(campaign, event_type)

    tasks = []
    if alert_emails:
        tasks.append(send_email_alert(alert_emails, subject, html))

    if webhook_url:
        payload = {
            "text": f"{emoji} *Campaign Alert*: {name} — {event_type} — {level}",
            "atip_data": {"campaign": name, "event": event_type, "level": level}
        }
        tasks.append(send_webhook_alert(webhook_url, payload))

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
