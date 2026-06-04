from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional
import json
from datetime import datetime, timezone

from ..services.campaign_detector import (
    detect_coordination, detect_infrastructure_overlap,
    infer_tactics, generate_campaign_summary,
    generate_evidence_hash, assess_campaign_threat_level
)
from ..services.evidence_packager import generate_evidence_package
from ..services.scanner import scan_url, scan_text, scan_domain
from ..utils.db import get_connection

router = APIRouter(prefix="/campaigns", tags=["campaigns"])


class CreateCampaignRequest(BaseModel):
    name: str
    description: Optional[str] = None
    target: Optional[str] = None
    target_type: Optional[str] = None


class AddEntityRequest(BaseModel):
    entity_input: str
    scan_type: str = "auto"
    role: str = "ACTOR"


class ExportRequest(BaseModel):
    recipient: Optional[str] = None
    package_type: str = "STANDARD"


def safe_parse_signals(signals_val) -> list:
    """Safely parse signals from DB — handles JSON string or list"""
    if not signals_val:
        return []
    if isinstance(signals_val, list):
        return signals_val
    if isinstance(signals_val, str):
        try:
            return json.loads(signals_val)
        except Exception:
            return []
    return []


@router.post("")
async def create_campaign(req: CreateCampaignRequest):
    try:
        conn = await get_connection()
        row = await conn.fetchrow("""
            INSERT INTO campaigns (name, description, target, target_type, status, threat_level)
            VALUES ($1, $2, $3, $4, 'ACTIVE', 'LOW')
            RETURNING *
        """, req.name, req.description, req.target, req.target_type)
        await conn.close()
        return dict(row)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("")
async def list_campaigns():
    try:
        conn = await get_connection()
        rows = await conn.fetch("SELECT * FROM campaigns ORDER BY last_activity DESC")
        await conn.close()
        return {"campaigns": [dict(r) for r in rows]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{campaign_id}")
async def get_campaign(campaign_id: str):
    try:
        conn = await get_connection()
        campaign = await conn.fetchrow("SELECT * FROM campaigns WHERE id = $1", campaign_id)
        if not campaign:
            await conn.close()
            raise HTTPException(status_code=404, detail="Campaign not found")

        entities = await conn.fetch(
            "SELECT * FROM campaign_entities WHERE campaign_id = $1 ORDER BY threat_score DESC",
            campaign_id
        )
        events = await conn.fetch(
            "SELECT * FROM campaign_events WHERE campaign_id = $1 ORDER BY created_at DESC LIMIT 50",
            campaign_id
        )
        await conn.close()

        entity_list = []
        for e in entities:
            d = dict(e)
            d["signals"] = safe_parse_signals(d.get("signals"))
            entity_list.append(d)

        return {
            "campaign": dict(campaign),
            "entities": entity_list,
            "events": [dict(ev) for ev in events],
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{campaign_id}/entities")
async def add_entity(campaign_id: str, req: AddEntityRequest, background_tasks: BackgroundTasks):
    # Verify campaign exists
    try:
        conn = await get_connection()
        campaign = await conn.fetchrow("SELECT * FROM campaigns WHERE id = $1", campaign_id)
        await conn.close()
        if not campaign:
            raise HTTPException(status_code=404, detail="Campaign not found")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Check for duplicate
    try:
        conn = await get_connection()
        existing = await conn.fetchrow(
            "SELECT id FROM campaign_entities WHERE campaign_id = $1 AND entity_input = $2",
            campaign_id, req.entity_input.strip()
        )
        await conn.close()
        if existing:
            raise HTTPException(
                status_code=409,
                detail=f"Entity '{req.entity_input.strip()}' already exists in this campaign"
            )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Scan entity
    input_val = req.entity_input.strip()
    try:
        if input_val.startswith("http"):
            scan_result = await scan_url(input_val)
        elif "." in input_val and " " not in input_val and len(input_val) < 100:
            scan_result = await scan_domain(input_val)
        else:
            scan_result = await scan_text(input_val)
    except Exception as e:
        scan_result = {
            "threat_score": 0, "entity_type": "UNKNOWN",
            "signals": [], "domain_intel": None
        }

    ip_addresses = []
    if scan_result.get("domain_intel"):
        ip_addresses = scan_result["domain_intel"].get("ip_addresses", [])

    signals_json = json.dumps(scan_result.get("signals", []))

    try:
        conn = await get_connection()
        entity_row = await conn.fetchrow("""
            INSERT INTO campaign_entities
            (campaign_id, entity_input, entity_type, role, threat_score, signals, ip_addresses)
            VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)
            RETURNING *
        """,
            campaign_id,
            input_val,
            scan_result.get("entity_type", "UNKNOWN"),
            req.role,
            float(scan_result.get("threat_score", 0)),
            signals_json,
            ip_addresses,
        )

        severity = (
            "CRITICAL" if scan_result.get("threat_score", 0) >= 75 else
            "WARNING" if scan_result.get("threat_score", 0) >= 50 else "INFO"
        )

        await conn.execute("""
            INSERT INTO campaign_events (campaign_id, entity_id, event_type, description, severity)
            VALUES ($1, $2, 'ENTITY_ADDED', $3, $4)
        """,
            campaign_id,
            entity_row["id"],
            f"Entity '{input_val[:50]}' added. Threat score: {scan_result.get('threat_score', 0):.1f}",
            severity
        )
        await conn.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    background_tasks.add_task(reanalyze_campaign, campaign_id)

    return {
        "entity": dict(entity_row),
        "scan_result": {
            "threat_score": scan_result.get("threat_score"),
            "threat_level": scan_result.get("threat_level"),
            "entity_type": scan_result.get("entity_type"),
            "summary": scan_result.get("summary"),
        },
        "message": "Entity added successfully"
    }


async def reanalyze_campaign(campaign_id: str):
    try:
        conn = await get_connection()
        entities = await conn.fetch(
            "SELECT * FROM campaign_entities WHERE campaign_id = $1", campaign_id
        )
        campaign = await conn.fetchrow("SELECT * FROM campaigns WHERE id = $1", campaign_id)

        if not entities or not campaign:
            await conn.close()
            return

        entity_dicts = []
        for e in entities:
            d = dict(e)
            d["signals"] = safe_parse_signals(d.get("signals"))
            entity_dicts.append(d)

        coordination_score, evidence = detect_coordination(entity_dicts)
        infrastructure_overlap = detect_infrastructure_overlap(entity_dicts)
        tactics = infer_tactics(entity_dicts, campaign.get("target"))
        avg_threat = sum(e.get("threat_score", 0) for e in entity_dicts) / len(entity_dicts)
        threat_level = assess_campaign_threat_level(
            len(entity_dicts), coordination_score, avg_threat, tactics
        )
        summary = generate_campaign_summary(
            campaign["name"], entity_dicts, campaign.get("target"),
            coordination_score, tactics, evidence
        )

        await conn.execute("""
            UPDATE campaigns SET
                entity_count = $1, coordination_score = $2,
                infrastructure_overlap = $3, tactics = $4,
                threat_level = $5, summary = $6,
                last_activity = NOW(), updated_at = NOW()
            WHERE id = $7
        """,
            len(entity_dicts), coordination_score, infrastructure_overlap,
            tactics, threat_level, summary, campaign_id
        )

        if threat_level != campaign.get("threat_level"):
            await conn.execute("""
                INSERT INTO campaign_events (campaign_id, event_type, description, severity)
                VALUES ($1, 'THREAT_LEVEL_CHANGE', $2, $3)
            """,
                campaign_id,
                f"Threat level: {campaign.get('threat_level')} → {threat_level}",
                "CRITICAL" if threat_level == "CRITICAL" else "WARNING"
            )

        await conn.close()
    except Exception as e:
        print(f"Reanalysis error: {e}")


@router.post("/{campaign_id}/export")
async def export_evidence(campaign_id: str, req: ExportRequest):
    try:
        conn = await get_connection()
        campaign = await conn.fetchrow("SELECT * FROM campaigns WHERE id = $1", campaign_id)
        if not campaign:
            await conn.close()
            raise HTTPException(status_code=404, detail="Campaign not found")

        entities = await conn.fetch(
            "SELECT * FROM campaign_entities WHERE campaign_id = $1", campaign_id
        )
        events = await conn.fetch(
            "SELECT * FROM campaign_events WHERE campaign_id = $1 ORDER BY created_at", campaign_id
        )

        campaign_dict = dict(campaign)
        entity_dicts = []
        for e in entities:
            d = dict(e)
            d["signals"] = safe_parse_signals(d.get("signals"))
            entity_dicts.append(d)
        event_dicts = [dict(ev) for ev in events]

        package = generate_evidence_package(
            campaign_dict, entity_dicts, event_dicts,
            recipient=req.recipient, package_type=req.package_type
        )

        pkg_hash = package["integrity"]["hash"]

        pkg_row = await conn.fetchrow("""
            INSERT INTO evidence_packages (campaign_id, package_type, recipient, content, hash, exported_at)
            VALUES ($1, $2, $3, $4::jsonb, $5, NOW())
            RETURNING id, created_at
        """,
            campaign_id, req.package_type, req.recipient,
            json.dumps(package, default=str), pkg_hash,
        )

        await conn.execute("""
            INSERT INTO campaign_events (campaign_id, event_type, description, severity)
            VALUES ($1, 'EVIDENCE_EXPORTED', $2, 'INFO')
        """,
            campaign_id,
            f"Evidence package exported. Type: {req.package_type}. Hash: {pkg_hash[:16]}..."
        )
        await conn.close()

        return {
            "package_id": str(pkg_row["id"]),
            "hash": pkg_hash,
            "package": package,
            "message": "Evidence package generated successfully"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
