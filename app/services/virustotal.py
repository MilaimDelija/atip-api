import httpx
import os
from typing import Dict, Optional, List

VT_BASE = "https://www.virustotal.com/api/v3"
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

HEADERS = {"x-apikey": VT_API_KEY}


async def get_vt_headers() -> Dict:
    key = os.getenv("VIRUSTOTAL_API_KEY", VT_API_KEY)
    return {"x-apikey": key}


async def scan_domain_vt(domain: str) -> Dict:
    """Get VirusTotal analysis for a domain"""
    headers = await get_vt_headers()
    result = {
        "source": "virustotal",
        "domain": domain,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "reputation": 0,
        "categories": [],
        "tags": [],
        "threat_names": [],
        "engines_flagged": [],
        "total_engines": 0,
        "last_analysis_date": None,
        "error": None,
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"{VT_BASE}/domains/{domain}",
                headers=headers
            )

            if resp.status_code == 404:
                result["error"] = "Domain not found in VirusTotal database"
                return result

            if resp.status_code == 401:
                result["error"] = "Invalid API key"
                return result

            if resp.status_code != 200:
                result["error"] = f"VT API error: {resp.status_code}"
                return result

            data = resp.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            result["malicious"] = stats.get("malicious", 0)
            result["suspicious"] = stats.get("suspicious", 0)
            result["harmless"] = stats.get("harmless", 0)
            result["undetected"] = stats.get("undetected", 0)
            result["reputation"] = attrs.get("reputation", 0)
            result["total_engines"] = sum(stats.values()) if stats else 0

            # Categories from different vendors
            cats = attrs.get("categories", {})
            result["categories"] = list(set(cats.values()))[:5]

            # Tags
            result["tags"] = attrs.get("tags", [])[:10]

            # Which engines flagged it
            engines = attrs.get("last_analysis_results", {})
            flagged = []
            threat_names = set()
            for engine, res in engines.items():
                if res.get("category") in ["malicious", "suspicious"]:
                    flagged.append(engine)
                    if res.get("result"):
                        threat_names.add(res["result"])
            result["engines_flagged"] = flagged[:10]
            result["threat_names"] = list(threat_names)[:5]

            # Last analysis date
            lad = attrs.get("last_analysis_date")
            if lad:
                from datetime import datetime, timezone
                result["last_analysis_date"] = datetime.fromtimestamp(
                    lad, tz=timezone.utc
                ).isoformat()

    except Exception as e:
        result["error"] = str(e)

    return result


async def scan_url_vt(url: str) -> Dict:
    """Submit URL to VirusTotal and get analysis"""
    headers = await get_vt_headers()
    result = {
        "source": "virustotal",
        "url": url,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "reputation": 0,
        "threat_names": [],
        "engines_flagged": [],
        "total_engines": 0,
        "error": None,
    }

    try:
        import base64
        # VT uses URL-safe base64 encoded URL as ID
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"{VT_BASE}/urls/{url_id}",
                headers=headers
            )

            if resp.status_code == 404:
                # Submit for scanning
                submit = await client.post(
                    f"{VT_BASE}/urls",
                    headers=headers,
                    data={"url": url}
                )
                if submit.status_code == 200:
                    result["error"] = "URL submitted for analysis — check again in 60 seconds"
                return result

            if resp.status_code != 200:
                result["error"] = f"VT API error: {resp.status_code}"
                return result

            data = resp.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            result["malicious"] = stats.get("malicious", 0)
            result["suspicious"] = stats.get("suspicious", 0)
            result["harmless"] = stats.get("harmless", 0)
            result["total_engines"] = sum(stats.values()) if stats else 0

            engines = attrs.get("last_analysis_results", {})
            flagged = []
            threat_names = set()
            for engine, res in engines.items():
                if res.get("category") in ["malicious", "suspicious"]:
                    flagged.append(engine)
                    if res.get("result"):
                        threat_names.add(res["result"])
            result["engines_flagged"] = flagged[:10]
            result["threat_names"] = list(threat_names)[:5]

    except Exception as e:
        result["error"] = str(e)

    return result


async def scan_ip_vt(ip: str) -> Dict:
    """Get VirusTotal analysis for an IP"""
    headers = await get_vt_headers()
    result = {
        "source": "virustotal",
        "ip": ip,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "reputation": 0,
        "country": None,
        "asn": None,
        "as_owner": None,
        "engines_flagged": [],
        "total_engines": 0,
        "error": None,
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"{VT_BASE}/ip_addresses/{ip}",
                headers=headers
            )

            if resp.status_code != 200:
                result["error"] = f"VT API error: {resp.status_code}"
                return result

            data = resp.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            result["malicious"] = stats.get("malicious", 0)
            result["suspicious"] = stats.get("suspicious", 0)
            result["harmless"] = stats.get("harmless", 0)
            result["reputation"] = attrs.get("reputation", 0)
            result["country"] = attrs.get("country")
            result["asn"] = attrs.get("asn")
            result["as_owner"] = attrs.get("as_owner")
            result["total_engines"] = sum(stats.values()) if stats else 0

            engines = attrs.get("last_analysis_results", {})
            flagged = [e for e, r in engines.items() if r.get("category") in ["malicious", "suspicious"]]
            result["engines_flagged"] = flagged[:10]

    except Exception as e:
        result["error"] = str(e)

    return result


def calculate_vt_threat_score(vt_result: Dict) -> tuple:
    """
    Convert VT result to ATIP threat score (0-100) and reasons
    Returns (score, confidence, reasons)
    """
    malicious = vt_result.get("malicious", 0)
    suspicious = vt_result.get("suspicious", 0)
    total = vt_result.get("total_engines", 1) or 1
    reputation = vt_result.get("reputation", 0)
    reasons = []

    score = 0.0

    if malicious > 0:
        ratio = malicious / total
        score += ratio * 80
        engines = vt_result.get("engines_flagged", [])[:3]
        reasons.append(f"{malicious}/{total} engines flagged as malicious ({', '.join(engines)})")

    if suspicious > 0:
        ratio = suspicious / total
        score += ratio * 40
        reasons.append(f"{suspicious}/{total} engines flagged as suspicious")

    if reputation < -10:
        score += min(abs(reputation) / 10, 20)
        reasons.append(f"Negative community reputation score: {reputation}")

    threat_names = vt_result.get("threat_names", [])
    if threat_names:
        reasons.append(f"Threat classifications: {', '.join(threat_names[:3])}")

    cats = vt_result.get("categories", [])
    bad_cats = ["phishing", "malware", "spam", "botnet", "c2", "ransomware"]
    bad_found = [c for c in cats if any(b in c.lower() for b in bad_cats)]
    if bad_found:
        score += 20
        reasons.append(f"Categorized as: {', '.join(bad_found)}")

    if not reasons:
        reasons.append(f"VirusTotal: {malicious} malicious, {suspicious} suspicious out of {total} engines")

    confidence = 0.95 if total > 10 else 0.7 if total > 0 else 0.3

    return min(score, 100), confidence, reasons
