from fastapi import APIRouter, HTTPException, BackgroundTasks
from ..models.schemas import ScanRequest, ScanType
from ..services.scanner import scan_url, scan_text, scan_domain
from ..utils.db import save_scan_result
import re

router = APIRouter(prefix="/scan", tags=["scan"])

def detect_input_type(input_str: str) -> ScanType:
    """Auto-detect input type if not specified"""
    input_str = input_str.strip()
    if re.match(r'^https?://', input_str):
        return ScanType.URL
    if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', input_str):
        return ScanType.DOMAIN
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', input_str):
        return ScanType.IP
    if '@' in input_str and '.' in input_str:
        return ScanType.EMAIL
    if len(input_str) > 100:
        return ScanType.TEXT
    return ScanType.USERNAME

@router.post("")
async def run_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Universal scan endpoint.
    Auto-detects input type or uses provided scan_type.
    """
    scan_type = request.scan_type
    input_val = request.input.strip()

    if not input_val:
        raise HTTPException(status_code=400, detail="Input cannot be empty")

    if len(input_val) > 50000:
        raise HTTPException(status_code=400, detail="Input too large (max 50KB)")

    try:
        if scan_type == ScanType.URL:
            result = await scan_url(input_val, deep=request.deep_scan)
        elif scan_type == ScanType.DOMAIN:
            result = await scan_domain(input_val)
        elif scan_type == ScanType.TEXT:
            result = await scan_text(input_val)
        else:
            # Auto-detect
            detected = detect_input_type(input_val)
            if detected == ScanType.URL:
                result = await scan_url(input_val, deep=request.deep_scan)
            elif detected == ScanType.DOMAIN:
                result = await scan_domain(input_val)
            else:
                result = await scan_text(input_val)

        # Save to DB in background
        background_tasks.add_task(save_scan_result, result)

        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/quick")
async def quick_scan(body: dict):
    """
    Quick scan — just provide {'input': '...'}, type is auto-detected.
    """
    input_val = body.get("input", "").strip()
    if not input_val:
        raise HTTPException(status_code=400, detail="input field required")

    detected = detect_input_type(input_val)
    request = ScanRequest(input=input_val, scan_type=detected)

    if detected == ScanType.URL:
        result = await scan_url(input_val)
    elif detected == ScanType.DOMAIN:
        result = await scan_domain(input_val)
    else:
        result = await scan_text(input_val)

    return result
