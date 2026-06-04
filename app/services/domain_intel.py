import asyncio
import socket
import re
from datetime import datetime, timezone
from typing import Optional, List, Dict
import httpx
import tldextract

# Known privacy/proxy WHOIS strings
PRIVACY_INDICATORS = [
    "privacy", "proxy", "redacted", "gdpr", "protected",
    "withheld", "data protected", "registration private",
]

SUSPICIOUS_REGISTRARS = [
    "namecheap", "namesilo", "porkbun",  # Often used for throwaway domains
]

DISPOSABLE_TLD = [".xyz", ".top", ".click", ".download", ".loan", ".online", ".site"]

async def get_whois_data(domain: str) -> Dict:
    """Get WHOIS data via whois.iana.org and fallback"""
    result = {
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "country": None,
        "nameservers": [],
        "is_privacy_protected": False,
        "raw": None,
    }

    try:
        import whois
        w = whois.whois(domain)
        if w:
            result["registrar"] = str(w.registrar) if w.registrar else None
            result["nameservers"] = list(w.name_servers or [])

            # Creation date
            cd = w.creation_date
            if isinstance(cd, list):
                cd = cd[0]
            if cd:
                result["creation_date"] = cd.isoformat() if hasattr(cd, 'isoformat') else str(cd)

            # Expiration date
            ed = w.expiration_date
            if isinstance(ed, list):
                ed = ed[0]
            if ed:
                result["expiration_date"] = ed.isoformat() if hasattr(ed, 'isoformat') else str(ed)

            # Privacy protection
            raw = str(w).lower()
            result["is_privacy_protected"] = any(p in raw for p in PRIVACY_INDICATORS)
            result["raw"] = str(w)[:500]
    except Exception as e:
        result["error"] = str(e)

    return result


async def resolve_ips(domain: str) -> List[str]:
    """Resolve domain to IPs"""
    try:
        loop = asyncio.get_event_loop()
        infos = await loop.getaddrinfo(domain, None)
        ips = list(set(info[4][0] for info in infos))
        return ips
    except Exception:
        return []


async def check_ip_reputation(ip: str) -> Dict:
    """Check IP reputation via AbuseIPDB-style heuristics"""
    result = {"is_vpn": False, "is_proxy": False, "reputation": 1.0, "country": None}
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            # ip-api.com free tier
            resp = await client.get(f"http://ip-api.com/json/{ip}?fields=status,country,isp,proxy,hosting")
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    result["country"] = data.get("country")
                    result["is_proxy"] = data.get("proxy", False)
                    result["is_hosting"] = data.get("hosting", False)
                    if data.get("proxy") or data.get("hosting"):
                        result["reputation"] = 0.4
    except Exception:
        pass
    return result


def calculate_domain_age(creation_date_str: Optional[str]) -> Optional[int]:
    """Returns age in days"""
    if not creation_date_str:
        return None
    try:
        cd = datetime.fromisoformat(creation_date_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        if cd.tzinfo is None:
            cd = cd.replace(tzinfo=timezone.utc)
        return (now - cd).days
    except Exception:
        return None


def detect_suspicious_flags(domain: str, whois: Dict, age_days: Optional[int]) -> List[str]:
    flags = []

    ext = tldextract.extract(domain)
    tld = f".{ext.suffix}"

    if tld in DISPOSABLE_TLD:
        flags.append(f"Suspicious TLD: {tld} — commonly used for spam/phishing")

    if age_days is not None and age_days < 30:
        flags.append(f"Very new domain: {age_days} days old — high risk")
    elif age_days is not None and age_days < 90:
        flags.append(f"Recently registered: {age_days} days old")

    if whois.get("is_privacy_protected"):
        flags.append("WHOIS privacy protection active — owner identity hidden")

    registrar = (whois.get("registrar") or "").lower()
    if any(r in registrar for r in SUSPICIOUS_REGISTRARS):
        flags.append(f"Registrar commonly used for throwaway domains: {whois.get('registrar')}")

    # Homograph/typosquat detection (simple)
    name = ext.domain.lower()
    common_targets = ["google","facebook","twitter","paypal","amazon","microsoft","apple","netflix"]
    for target in common_targets:
        if name != target and (
            target in name or
            sum(1 for a, b in zip(name, target) if a != b) <= 2
        ):
            flags.append(f"Possible typosquatting of '{target}'")
            break

    return flags


async def analyze_domain(domain: str) -> Dict:
    """Full domain intelligence analysis"""
    # Clean domain
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0].strip()

    whois_data = await get_whois_data(domain)
    ips = await resolve_ips(domain)
    age_days = calculate_domain_age(whois_data.get("creation_date"))
    flags = detect_suspicious_flags(domain, whois_data, age_days)

    # Check IP reputations
    ip_reputations = []
    for ip in ips[:3]:  # Check max 3 IPs
        rep = await check_ip_reputation(ip)
        ip_reputations.append(rep)

    return {
        "domain": domain,
        "registrar": whois_data.get("registrar"),
        "creation_date": whois_data.get("creation_date"),
        "expiration_date": whois_data.get("expiration_date"),
        "country": whois_data.get("country") or (ip_reputations[0].get("country") if ip_reputations else None),
        "nameservers": [ns.lower() for ns in whois_data.get("nameservers", [])[:4]],
        "ip_addresses": ips[:5],
        "is_privacy_protected": whois_data.get("is_privacy_protected", False),
        "age_days": age_days,
        "suspicion_flags": flags,
        "ip_reputations": ip_reputations,
    }
