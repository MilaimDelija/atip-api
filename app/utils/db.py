import os
import asyncpg
from typing import Optional, Dict, List
import json

DATABASE_URL = os.getenv("DATABASE_URL", "")

async def get_connection():
    """Get a database connection"""
    if not DATABASE_URL:
        raise Exception("DATABASE_URL not configured")
    return await asyncpg.connect(DATABASE_URL)

async def save_scan_result(result: Dict):
    """Save scan result to detections table"""
    if not DATABASE_URL:
        return
    try:
        conn = await get_connection()
        await conn.execute("""
            INSERT INTO detections (
                input_text, threat_score, threat_level,
                entity_type, signals, summary, api_tier
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        """,
            result.get("input", "")[:2000],
            int(result.get("threat_score", 0)),
            result.get("threat_level", "LOW"),
            result.get("entity_type", "UNKNOWN"),
            json.dumps(result.get("signals", [])),
            result.get("summary", ""),
            "api",
        )
        await conn.close()
    except Exception as e:
        print(f"DB save error: {e}")

async def get_recent_scans(limit: int = 20) -> List[Dict]:
    """Get recent scans from detections table"""
    if not DATABASE_URL:
        return []
    try:
        conn = await get_connection()
        rows = await conn.fetch("""
            SELECT id, created_at, input_text, threat_score,
                   threat_level, entity_type, summary
            FROM detections
            ORDER BY created_at DESC
            LIMIT $1
        """, limit)
        await conn.close()
        return [dict(row) for row in rows]
    except Exception as e:
        print(f"DB fetch error: {e}")
        return []
