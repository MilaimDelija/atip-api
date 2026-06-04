from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional
import uuid
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


# --- Campaign CRUD ---

@router.post("")
async def create_campaign(req: CreateCampaignRequest):
    """Create a new campaign tracking session"""
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
    """List all campaigns"""
    try:
        conn = await get_connection()
        rows = await conn.fetch("""
            SELECT * FROM campaigns ORDER BY last_activity DESC
        """)
        await conn.close()
        return {"campaigns": [dict(r) for r in rows]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{campaign_id}")
async def get_campaign(campaign_id: str):
    """Get full campaign details with entities and events"""
    try:
        conn = await get_connection()

        campaign = await conn.fetchrow(
            "SELECT * FROM campaigns WHERE id = $1", campaign_id
        )
        if not campaign:
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

        return {
            "campaign": dict(campaign),
            "entities": [dict(e) for e in entities],
            "events": [dict(ev) for ev in events],
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- Entity Management ---

@router.post("/{campaign_id}/entities")
async def add_entity(campaign_id: str, req: AddEntityRequest, background_tasks: BackgroundTasks):
    """
    Add an entity to a campaign.
    Automatically scans the entity and updates campaign analysis.
    """
    try:
        conn = await get_connection()
        campaign = await conn.fetchrow("SELECT * FROM campaigns WHERE id = $1", campaign_id)
        if not campaign:
            await conn.close()
            raise HTTPException(status_code=404, detail="Campaign not found")
        await conn.close()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Scan the entity
    input_val = req.entity_input.strip()
    try:
        if req.scan_type == "url" or input_val.startswith("http"):
            scan_result = await scan_url(input_val)
        elif req.scan_type == "domain" or ("." in input_val and " " not in input_val and not input_val.startswith("http")):
            scan_result = await scan_domain(input_val)
        else:
            scan_result = await scan_text(input_val)
    except Exception as e:
        scan_result = {
            "threat_score": 0, "entity_type": "UNKNOWN",
            "signals": [], "domain_intel": None
        }

    # Extract IPs from scan
    ip_addresses = []
    if scan_result.get("domain_intel"):
        ip_addresses = scan_result["domain_intel"].get("ip_addresses", [])

    try:
        conn = await get_connection()

        # Save entity
        entity_row = await conn.fetchrow("""
            INSERT INTO campaign_entities
            (campaign_id, entity_input, entity_type, role, threat_score, signals, ip_addresses)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
        """,
            campaign_id,
            input_val,
            scan_result.get("entity_type", "UNKNOWN"),
            req.role,
            float(scan_result.get("threat_score", 0)),
            str(scan_result.get("signals", [])),
            ip_addresses,
        )

        # Log event
        await conn.execute("""
            INSERT INTO campaign_events (campaign_id, entity_id, event_type, description, severity)
            VALUES ($1, $2, 'ENTITY_ADDED', $3, $4)
        """,
            campaign_id,
            entity_row["id"],
            f"Entity '{input_val[:50]}' added. Threat score: {scan_result.get('threat_score', 0):.1f}",
            "CRITICAL" if scan_result.get("threat_score", 0) >= 75 else
            "WARNING" if scan_result.get("threat_score", 0) >= 50 else "INFO"
        )

        await conn.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Reanalyze campaign in background
    background_tasks.add_task(reanalyze_campaign, campaign_id)

    return {
        "entity": dict(entity_row),
        "scan_result": scan_result,
        "message": "Entity added and campaign analysis updated"
    }


async def reanalyze_campaign(campaign_id: str):
    """Recompute campaign metrics after entity changes"""
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
            # Parse signals from string if needed
            try:
                import json
                if isinstance(d.get("signals"), str):
                    d["signals"] = json.loads(d["signals"].replace("'", '"'))
            except Exception:
                d["signals"] = []
            entity_dicts.append(d)

        # Compute metrics
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

        # Update campaign
        await conn.execute("""
            UPDATE campaigns SET
                entity_count = $1,
                coordination_score = $2,
                infrastructure_overlap = $3,
                tactics = $4,
                threat_level = $5,
                summary = $6,
                last_activity = NOW(),
                updated_at = NOW()
            WHERE id = $7
        """,
            len(entity_dicts),
            coordination_score,
            infrastructure_overlap,
            tactics,
            threat_level,
            summary,
            campaign_id
        )

        # Log if threat level changed
        if threat_level != campaign.get("threat_level"):
            await conn.execute("""
                INSERT INTO campaign_events (campaign_id, event_type, description, severity)
                VALUES ($1, 'THREAT_LEVEL_CHANGE', $2, $3)
            """,
                campaign_id,
                f"Threat level changed: {campaign.get('threat_level')} → {threat_level}",
                "CRITICAL" if threat_level == "CRITICAL" else "WARNING"
            )

        await conn.close()
    except Exception as e:
        print(f"Reanalysis error: {e}")


# --- Evidence Export ---

@router.post("/{campaign_id}/export")
async def export_evidence(campaign_id: str, req: ExportRequest):
    """Generate legally-formatted evidence package"""
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
        entity_dicts = [dict(e) for e in entities]
        event_dicts = [dict(ev) for ev in events]

        package = generate_evidence_package(
            campaign_dict, entity_dicts, event_dicts,
            recipient=req.recipient, package_type=req.package_type
        )

        pkg_hash = package["integrity"]["hash"]

        # Save package record
        pkg_row = await conn.fetchrow("""
            INSERT INTO evidence_packages (campaign_id, package_type, recipient, content, hash, exported_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
            RETURNING id, created_at
        """,
            campaign_id,
            req.package_type,
            req.recipient,
            str(package),
            pkg_hash,
        )

        # Log export event
        await conn.execute("""
            INSERT INTO campaign_events (campaign_id, event_type, description, severity)
            VALUES ($1, 'EVIDENCE_EXPORTED', $2, 'INFO')
        """,
            campaign_id,
            f"Evidence package exported. Type: {req.package_type}. Recipient: {req.recipient or 'unspecified'}. Hash: {pkg_hash[:16]}..."
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
