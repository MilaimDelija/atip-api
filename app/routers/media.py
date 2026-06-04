from fastapi import APIRouter, HTTPException, UploadFile, File
from fastapi.responses import JSONResponse
from typing import Optional
from ..services.media_forensics import analyze_media, detect_file_type

router = APIRouter(prefix="/media", tags=["media"])

MAX_SIZE = 50 * 1024 * 1024  # 50MB
ALLOWED_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp", "video/mp4"}


@router.post("/analyze")
async def analyze_media_file(file: UploadFile = File(...)):
    """
    Analyze image or video for manipulation, deepfakes, and metadata forensics.
    Extracts EXIF, detects AI generation, flags editing software.
    Max size: 50MB
    """
    data = await file.read()

    if len(data) > MAX_SIZE:
        raise HTTPException(status_code=413, detail="File too large (max 50MB)")

    file_type = detect_file_type(data, file.filename or "")
    if file_type not in ALLOWED_TYPES and file_type != "unknown":
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported file type: {file_type}. Allowed: JPEG, PNG, GIF, WEBP, MP4"
        )

    try:
        result = await analyze_media(data, file.filename or "")
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status")
async def media_status():
    return {
        "service": "ATIP Media Forensics",
        "version": "1.0",
        "capabilities": [
            "EXIF metadata extraction",
            "AI generation detection (software signatures)",
            "Timestamp inconsistency detection",
            "Image dimension analysis (AI size patterns)",
            "JPEG re-compression detection",
            "Video metadata extraction",
            "SHA-256 + perceptual hash",
            "Manipulation scoring 0-100",
        ],
        "supported_formats": ["JPEG", "PNG", "GIF", "WEBP", "MP4", "MOV"],
        "max_size_mb": 50,
    }
