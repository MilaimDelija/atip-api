import hashlib
import io
import os
import re
import struct
from typing import Dict, List, Optional, Tuple
from datetime import datetime


# ── Helpers ────────────────────────────────────────────────────────────────

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def phash_simple(data: bytes) -> str:
    """Simple perceptual hash — detects near-duplicate images"""
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(data)).convert("L").resize((8, 8))
        pixels = list(img.getdata())
        avg = sum(pixels) / len(pixels)
        bits = "".join("1" if p > avg else "0" for p in pixels)
        return hex(int(bits, 2))[2:].zfill(16)
    except Exception:
        return ""


# ── EXIF / Image Analysis ──────────────────────────────────────────────────

SUSPICIOUS_SOFTWARE = [
    "photoshop", "gimp", "affinity", "facetune", "faceapp",
    "deepfake", "reface", "avatarify", "stable diffusion",
    "midjourney", "dall-e", "firefly", "canva",
]

AI_GEN_SOFTWARE = [
    "stable diffusion", "midjourney", "dall-e", "firefly",
    "adobe firefly", "ideogram", "leonardo",
]


def extract_exif(data: bytes) -> Dict:
    """Extract EXIF metadata from image bytes"""
    result = {
        "has_exif": False,
        "make": None,
        "model": None,
        "software": None,
        "datetime_original": None,
        "datetime_digitized": None,
        "datetime_modified": None,
        "gps_latitude": None,
        "gps_longitude": None,
        "gps_altitude": None,
        "orientation": None,
        "width": None,
        "height": None,
        "color_space": None,
        "flash": None,
        "focal_length": None,
        "iso": None,
        "exposure_time": None,
        "user_comment": None,
        "raw_tags": {},
    }

    try:
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS

        img = Image.open(io.BytesIO(data))
        result["width"], result["height"] = img.size

        exif_data = img._getexif()
        if not exif_data:
            return result

        result["has_exif"] = True
        raw = {}

        for tag_id, value in exif_data.items():
            tag = TAGS.get(tag_id, str(tag_id))
            raw[tag] = str(value)[:200] if not isinstance(value, bytes) else f"<binary {len(value)} bytes>"

            if tag == "Make": result["make"] = str(value)[:50]
            elif tag == "Model": result["model"] = str(value)[:50]
            elif tag == "Software": result["software"] = str(value)[:100]
            elif tag == "DateTimeOriginal": result["datetime_original"] = str(value)
            elif tag == "DateTimeDigitized": result["datetime_digitized"] = str(value)
            elif tag == "DateTime": result["datetime_modified"] = str(value)
            elif tag == "Orientation": result["orientation"] = int(value) if isinstance(value, int) else None
            elif tag == "ColorSpace": result["color_space"] = str(value)
            elif tag == "Flash": result["flash"] = str(value)
            elif tag == "FocalLength": result["focal_length"] = str(value)
            elif tag == "ISOSpeedRatings": result["iso"] = int(value) if isinstance(value, int) else None
            elif tag == "ExposureTime": result["exposure_time"] = str(value)
            elif tag == "UserComment":
                try:
                    result["user_comment"] = value.decode("utf-8", errors="ignore")[:200]
                except Exception:
                    result["user_comment"] = str(value)[:200]
            elif tag == "GPSInfo":
                try:
                    gps = {}
                    for gps_id, gps_val in value.items():
                        gps[GPSTAGS.get(gps_id, gps_id)] = gps_val

                    def dms_to_decimal(dms, ref):
                        d, m, s = dms
                        decimal = float(d) + float(m) / 60 + float(s) / 3600
                        if ref in ("S", "W"):
                            decimal = -decimal
                        return round(decimal, 6)

                    if "GPSLatitude" in gps and "GPSLatitudeRef" in gps:
                        result["gps_latitude"] = dms_to_decimal(gps["GPSLatitude"], gps["GPSLatitudeRef"])
                    if "GPSLongitude" in gps and "GPSLongitudeRef" in gps:
                        result["gps_longitude"] = dms_to_decimal(gps["GPSLongitude"], gps["GPSLongitudeRef"])
                    if "GPSAltitude" in gps:
                        result["gps_altitude"] = float(gps["GPSAltitude"])
                except Exception:
                    pass

        result["raw_tags"] = dict(list(raw.items())[:30])

    except Exception as e:
        result["error"] = str(e)

    return result


def detect_image_manipulation(exif: Dict, data: bytes) -> Tuple[float, List[str]]:
    """
    Analyze EXIF and image data for manipulation indicators.
    Returns (suspicion_score 0-100, flags list)
    """
    flags = []
    score = 0.0

    software = (exif.get("software") or "").lower()
    make = (exif.get("make") or "").lower()

    # AI-generated detection
    for ai_sw in AI_GEN_SOFTWARE:
        if ai_sw in software:
            score += 60
            flags.append(f"AI image generation software detected in metadata: '{exif.get('software')}'")
            break

    # Photo editing software
    for sus_sw in SUSPICIOUS_SOFTWARE:
        if sus_sw in software and sus_sw not in AI_GEN_SOFTWARE:
            score += 25
            flags.append(f"Image editing software detected: '{exif.get('software')}'")
            break

    # No EXIF at all (stripped) — suspicious for shared images
    if not exif.get("has_exif"):
        score += 15
        flags.append("No EXIF metadata — may have been stripped to hide origin")

    # Timestamp inconsistencies
    dt_orig = exif.get("datetime_original")
    dt_mod = exif.get("datetime_modified")
    if dt_orig and dt_mod and dt_orig != dt_mod:
        score += 20
        flags.append(f"Timestamp inconsistency: taken {dt_orig} but modified {dt_mod}")

    # No camera make/model but has EXIF (possibly synthetic)
    if exif.get("has_exif") and not make and not exif.get("model"):
        score += 15
        flags.append("EXIF present but no camera make/model — possibly synthetic")

    # Unusual dimensions (AI images often have specific sizes)
    w, h = exif.get("width"), exif.get("height")
    if w and h:
        ai_dims = [(512, 512), (768, 768), (1024, 1024), (1024, 768), (768, 1024),
                   (512, 768), (768, 512), (1536, 1024), (1024, 1536)]
        if (w, h) in ai_dims:
            score += 20
            flags.append(f"Image dimensions {w}x{h} — common AI generation output size")

    # Check for JPEG compression artifacts (ELA-like simple check)
    if data[:3] == b'\xff\xd8\xff':  # JPEG magic bytes
        # Count JPEG restart markers — too many can indicate re-compression
        restart_count = data.count(b'\xff\xd0') + data.count(b'\xff\xd1') + data.count(b'\xff\xd2')
        if restart_count > 20:
            score += 10
            flags.append(f"Multiple JPEG restart markers ({restart_count}) — possible re-compression")

    return min(score, 100), flags


# ── Video Metadata Analysis ────────────────────────────────────────────────

VIDEO_EDITING_TOOLS = [
    "premiere", "final cut", "davinci", "after effects", "sony vegas",
    "capcut", "tiktok", "instagram", "snapchat", "facetune",
    "deepfacelab", "faceswap", "reface",
]

def analyze_video_metadata(data: bytes, filename: str = "") -> Dict:
    """Extract and analyze video metadata"""
    result = {
        "format": None,
        "duration": None,
        "width": None,
        "height": None,
        "codec": None,
        "bitrate": None,
        "creation_time": None,
        "encoder": None,
        "software": None,
        "tags": {},
        "flags": [],
        "suspicion_score": 0,
    }

    try:
        import mutagen
        from mutagen.mp4 import MP4
        from mutagen.mp3 import MP3

        ext = filename.lower().split(".")[-1] if "." in filename else ""

        if ext in ("mp4", "m4v", "mov") or data[:4] in (b'ftyp', b'\x00\x00\x00\x1c', b'\x00\x00\x00\x18'):
            # Try MP4 parsing
            try:
                f = MP4(fileobj=io.BytesIO(data))
                tags = f.tags or {}
                result["format"] = "MP4/MOV"

                # Extract creation time
                ct = tags.get("\xa9day", [None])[0]
                if ct:
                    result["creation_time"] = str(ct)

                # Encoder/software
                enc = tags.get("\xa9too", [None])[0]
                if enc:
                    result["encoder"] = str(enc)
                    for tool in VIDEO_EDITING_TOOLS:
                        if tool in str(enc).lower():
                            result["suspicion_score"] += 20
                            result["flags"].append(f"Video editing tool detected: '{enc}'")

                result["tags"] = {k: str(v) for k, v in list(tags.items())[:15]}
            except Exception:
                pass

        # Simple MP4 box parser for additional metadata
        if b'moov' in data[:50000]:
            result["format"] = result.get("format") or "MP4"

        # Check for deepfake tool signatures in binary
        binary_str = data[:10000]
        for tool in ["deepfacelab", "faceswap", "reface", "avatarify"]:
            if tool.encode() in binary_str.lower():
                result["suspicion_score"] += 50
                result["flags"].append(f"Deepfake tool signature found in file: '{tool}'")

    except Exception as e:
        result["error"] = str(e)

    return result


# ── Full Media Analysis ────────────────────────────────────────────────────

def detect_file_type(data: bytes, filename: str = "") -> str:
    """Detect file type from magic bytes"""
    if data[:2] == b'\xff\xd8': return "image/jpeg"
    if data[:8] == b'\x89PNG\r\n\x1a\n': return "image/png"
    if data[:6] in (b'GIF87a', b'GIF89a'): return "image/gif"
    if data[:4] == b'RIFF' and data[8:12] == b'WEBP': return "image/webp"
    if data[:4] in (b'ftyp', b'\x00\x00\x00\x1c'): return "video/mp4"
    if data[:3] == b'ID3' or data[:2] == b'\xff\xfb': return "audio/mp3"
    ext = filename.lower().split(".")[-1] if "." in filename else ""
    type_map = {"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
                "gif": "image/gif", "mp4": "video/mp4", "mov": "video/mp4",
                "webp": "image/webp", "mp3": "audio/mp3"}
    return type_map.get(ext, "unknown")


async def analyze_media(data: bytes, filename: str = "") -> Dict:
    """Full media forensics analysis"""
    file_hash = sha256_bytes(data)
    file_type = detect_file_type(data, filename)
    file_size = len(data)

    result = {
        "filename": filename,
        "file_type": file_type,
        "file_size_bytes": file_size,
        "file_size_human": f"{file_size / 1024:.1f} KB" if file_size < 1024*1024 else f"{file_size / 1024 / 1024:.1f} MB",
        "sha256": file_hash,
        "phash": "",
        "threat_score": 0.0,
        "threat_level": "LOW",
        "manipulation_flags": [],
        "exif": {},
        "video_meta": {},
        "summary": "",
        "recommendations": [],
    }

    flags = []
    score = 0.0

    if file_type.startswith("image/"):
        # Image analysis
        result["phash"] = phash_simple(data)
        exif = extract_exif(data)
        result["exif"] = exif
        img_score, img_flags = detect_image_manipulation(exif, data)
        score += img_score
        flags.extend(img_flags)

    elif file_type.startswith("video/"):
        # Video analysis
        video_meta = analyze_video_metadata(data, filename)
        result["video_meta"] = video_meta
        score += video_meta.get("suspicion_score", 0)
        flags.extend(video_meta.get("flags", []))

    # File size anomalies
    if file_type.startswith("image/") and file_size < 5000:
        score += 10
        flags.append("Unusually small image — may be placeholder or test file")

    result["manipulation_flags"] = flags
    result["threat_score"] = round(min(score, 100), 1)
    result["threat_level"] = (
        "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"
    )

    # Summary
    if flags:
        result["summary"] = f"Detected {len(flags)} manipulation indicator(s). {result['threat_level']} risk."
    else:
        result["summary"] = "No significant manipulation indicators detected."

    # Recommendations
    if score >= 50:
        result["recommendations"].append("Do not share or republish this media without verification")
        result["recommendations"].append("Report to platform content moderation team")
        result["recommendations"].append("Preserve original file as evidence (SHA-256 hash documented)")
    if score >= 25:
        result["recommendations"].append("Verify media origin through reverse image/video search")
        result["recommendations"].append("Check original source before trusting content")
    if not result["recommendations"]:
        result["recommendations"].append("Media appears authentic — continue monitoring")

    return result
