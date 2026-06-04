import httpx
import os
import asyncio
from typing import Dict, List, Optional

SHODAN_KEY = os.getenv("SHODAN_API_KEY", "")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

# Ports commonly associated with malicious activity
SUSPICIOUS_PORTS = {
    23: "Telnet — often used by IoT botnets",
    445: "SMB — WannaCry/EternalBlue target",
    1433: "MSSQL — common brute force target",
    3389: "RDP — ransomware entry point",
    4444: "Metasploit default listener",
    6667: "IRC — classic botnet C2 channel",
    6666: "IRC botnet C2",
    8080: "HTTP proxy — often used for anonymization",
    9001: "Tor relay port",
    9050: "Tor SOCKS proxy",
    31337: "Back Orifice RAT",
    12345: "NetBus RAT",
}

# Software/banners indicating suspicious activity
SUSPICIOUS_BANNERS = [
    "mirai", "botnet", "c2", "metasploit", "cobalt strike",
    "empire", "cobaltstrike", "meterpreter", "beacon"
]

# Known malicious ASNs (bulletproof hosting)
SUSPICIOUS_ASNS = [
    "AS209588",  # Flyservers
    "AS62282",   # Serverius
    "AS197328",  # Selectel
    "AS9009",    # M247
    "AS60068",   # Datacamp Limited
]


async def get_shodan_host(ip: str) -> Dict:
    """Get Shodan host intelligence for an IP"""
    key = os.getenv("SHODAN_API_KEY", SHODAN_KEY)
    result = {
        "source": "shodan",
        "ip": ip,
        "ports": [],
        "hostnames": [],
        "domains": [],
        "country": None,
        "city": None,
        "org": None,
        "isp": None,
        "asn": None,
        "os": None,
        "tags": [],
        "vulns": [],
        "services": [],
        "last_update": None,
        "error": None,
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": key}
            )

            if resp.status_code == 404:
                result["error"] = "IP not in Shodan database"
                return result
            if resp.status_code == 401:
                result["error"] = "Invalid Shodan API key"
                return result
            if resp.status_code != 200:
                result["error"] = f"Shodan error: {resp.status_code}"
                return result

            data = resp.json()

            result["ports"] = data.get("ports", [])
            result["hostnames"] = data.get("hostnames", [])[:5]
            result["domains"] = data.get("domains", [])[:5]
            result["country"] = data.get("country_name")
            result["city"] = data.get("city")
            result["org"] = data.get("org")
            result["isp"] = data.get("isp")
            result["asn"] = data.get("asn")
            result["os"] = data.get("os")
            result["tags"] = data.get("tags", [])
            result["last_update"] = data.get("last_update")

            # CVEs/vulnerabilities
            vulns = data.get("vulns", {})
            result["vulns"] = list(vulns.keys())[:10] if isinstance(vulns, dict) else []

            # Extract service banners
            services = []
            for item in data.get("data", [])[:10]:
                svc = {
                    "port": item.get("port"),
                    "transport": item.get("transport", "tcp"),
                    "product": item.get("product"),
                    "version": item.get("version"),
                    "banner": (item.get("data", "") or "")[:200],
                }
                services.append(svc)
            result["services"] = services

    except Exception as e:
        result["error"] = str(e)

    return result


async def get_geolocation(ip: str) -> Dict:
    """Get IP geolocation via ip-api.com (free, no key needed)"""
    result = {
        "source": "ip-api",
        "ip": ip,
        "country": None,
        "country_code": None,
        "region": None,
        "city": None,
        "isp": None,
        "org": None,
        "is_proxy": False,
        "is_hosting": False,
        "is_mobile": False,
        "timezone": None,
        "error": None,
    }

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,country,countryCode,regionName,city,isp,org,proxy,hosting,mobile,timezone,query"}
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    result["country"] = data.get("country")
                    result["country_code"] = data.get("countryCode")
                    result["region"] = data.get("regionName")
                    result["city"] = data.get("city")
                    result["isp"] = data.get("isp")
                    result["org"] = data.get("org")
                    result["is_proxy"] = data.get("proxy", False)
                    result["is_hosting"] = data.get("hosting", False)
                    result["is_mobile"] = data.get("mobile", False)
                    result["timezone"] = data.get("timezone")
    except Exception as e:
        result["error"] = str(e)

    return result


async def get_abuseipdb(ip: str) -> Dict:
    """Check AbuseIPDB for abuse reports"""
    key = os.getenv("ABUSEIPDB_API_KEY", ABUSEIPDB_KEY)
    result = {
        "source": "abuseipdb",
        "ip": ip,
        "abuse_score": 0,
        "total_reports": 0,
        "last_reported": None,
        "categories": [],
        "is_tor": False,
        "is_public": True,
        "error": None,
    }

    if not key:
        result["error"] = "No AbuseIPDB key configured"
        return result

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                result["abuse_score"] = data.get("abuseConfidenceScore", 0)
                result["total_reports"] = data.get("totalReports", 0)
                result["last_reported"] = data.get("lastReportedAt")
                result["is_tor"] = data.get("isTor", False)
                result["is_public"] = data.get("isPublic", True)
                cats = data.get("reports", [])
                all_cats = set()
                for r in cats[:20]:
                    all_cats.update(r.get("categories", []))
                result["categories"] = list(all_cats)
    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_suspicious_ports(ports: List[int]) -> List[str]:
    """Flag suspicious open ports"""
    flags = []
    for port in ports:
        if port in SUSPICIOUS_PORTS:
            flags.append(f"Port {port} open: {SUSPICIOUS_PORTS[port]}")
    return flags


def analyze_banners(services: List[Dict]) -> List[str]:
    """Detect malicious software in service banners"""
    flags = []
    for svc in services:
        banner = (svc.get("banner") or "").lower()
        product = (svc.get("product") or "").lower()
        for keyword in SUSPICIOUS_BANNERS:
            if keyword in banner or keyword in product:
                flags.append(f"Suspicious software detected on port {svc.get('port')}: '{keyword}'")
    return flags


def calculate_ip_threat_score(
    shodan: Dict,
    geo: Dict,
    abuse: Dict,
    vt: Optional[Dict] = None
) -> tuple:
    """Calculate overall IP threat score (0-100) and reasons"""
    score = 0.0
    reasons = []
    confidence = 0.5

    # AbuseIPDB score (highest weight if available)
    abuse_score = abuse.get("abuse_score", 0)
    if abuse_score > 0 and not abuse.get("error"):
        score += abuse_score * 0.4
        reports = abuse.get("total_reports", 0)
        if reports > 0:
            reasons.append(f"AbuseIPDB: {abuse_score}% abuse confidence, {reports} reports")
        if abuse.get("is_tor"):
            score += 15
            reasons.append("Tor exit node detected")
        confidence = 0.90

    # Shodan analysis
    if not shodan.get("error"):
        confidence = max(confidence, 0.75)
        port_flags = analyze_suspicious_ports(shodan.get("ports", []))
        if port_flags:
            score += min(len(port_flags) * 12, 30)
            reasons.extend(port_flags[:3])

        banner_flags = analyze_banners(shodan.get("services", []))
        if banner_flags:
            score += min(len(banner_flags) * 20, 40)
            reasons.extend(banner_flags[:2])

        vulns = shodan.get("vulns", [])
        if vulns:
            score += min(len(vulns) * 8, 25)
            reasons.append(f"{len(vulns)} CVE(s) detected: {', '.join(vulns[:3])}")

        tags = shodan.get("tags", [])
        bad_tags = ["malware", "botnet", "c2", "compromised", "scanner"]
        bad_found = [t for t in tags if any(b in t.lower() for b in bad_tags)]
        if bad_found:
            score += 25
            reasons.append(f"Shodan tags: {', '.join(bad_found)}")

        asn = shodan.get("asn", "")
        if asn in SUSPICIOUS_ASNS:
            score += 20
            reasons.append(f"Hosted on known bulletproof hosting ASN: {asn}")

    # Geolocation flags
    if not geo.get("error"):
        if geo.get("is_proxy"):
            score += 15
            reasons.append("VPN/Proxy detected — identity obfuscation")
        if geo.get("is_hosting"):
            score += 10
            reasons.append("Hosted on datacenter/cloud infrastructure")

    # VT
    if vt and not vt.get("error"):
        vt_mal = vt.get("malicious", 0)
        if vt_mal > 0:
            score += vt_mal * 5
            reasons.append(f"VirusTotal: {vt_mal} engines flagged this IP")
            confidence = max(confidence, 0.90)

    if not reasons:
        reasons.append("No significant threat indicators found for this IP")

    return min(score, 100), confidence, reasons


async def full_ip_analysis(ip: str) -> Dict:
    """Complete IP intelligence analysis"""
    # Run all checks in parallel
    shodan_task = get_shodan_host(ip)
    geo_task = get_geolocation(ip)
    abuse_task = get_abuseipdb(ip)

    shodan_result, geo_result, abuse_result = await asyncio.gather(
        shodan_task, geo_task, abuse_task
    )

    # VT IP scan (already have this)
    from .virustotal import scan_ip_vt
    vt_result = await scan_ip_vt(ip)

    threat_score, confidence, reasons = calculate_ip_threat_score(
        shodan_result, geo_result, abuse_result, vt_result
    )

    return {
        "ip": ip,
        "threat_score": round(threat_score, 1),
        "confidence": confidence,
        "reasons": reasons,
        "shodan": shodan_result,
        "geolocation": geo_result,
        "abuseipdb": abuse_result,
        "virustotal": vt_result,
        "open_ports": shodan_result.get("ports", []),
        "country": geo_result.get("country") or shodan_result.get("country"),
        "org": shodan_result.get("org") or geo_result.get("org"),
        "is_proxy": geo_result.get("is_proxy", False),
        "is_hosting": geo_result.get("is_hosting", False),
        "is_tor": abuse_result.get("is_tor", False),
        "vulns": shodan_result.get("vulns", []),
        "tags": shodan_result.get("tags", []),
    }
