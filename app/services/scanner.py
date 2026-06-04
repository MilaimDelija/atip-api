import uuid
import time
from typing import Dict, Optional
from datetime import datetime

from .text_analysis import analyze_text
from .domain_intel import analyze_domain
from .web_scraper import scrape_url, check_url_reputation
from .network_graph import build_entity_graph
from ..models.schemas import ScanType, ThreatLevel, EntityType


def calculate_threat_score(signals: list) -> float:
    weights = {
        "linguistic": 0.20,
        "domain": 0.25,
        "url_reputation": 0.20,
        "content": 0.20,
        "network": 0.15,
    }
    total_score = 0.0
    total_weight = 0.0
    for signal in signals:
        name = signal.get("name", "")
        w = weights.get(name, 0.1)
        conf = signal.get("confidence", 0.5)
        if conf > 0:
            total_score += signal.get("score", 0) * w * conf
            total_weight += w * conf
    return round(total_score / total_weight, 1) if total_weight > 0 else 0.0


def get_threat_level(score: float) -> str:
    if score >= 75: return "CRITICAL"
    if score >= 50: return "HIGH"
    if score >= 25: return "MEDIUM"
    return "LOW"


def get_entity_type(signals: list, scan_type: str) -> str:
    linguistic = next((s for s in signals if s["name"] == "linguistic"), None)
    domain = next((s for s in signals if s["name"] == "domain"), None)

    if linguistic and linguistic["score"] > 70:
        return "AI_AGENT"
    if domain and domain["score"] > 60:
        return "BOT"
    if linguistic and linguistic["score"] > 40:
        return "SYNTHETIC_PERSONA"
    return "UNKNOWN"


def generate_recommendations(signals: list, threat_level: str) -> list:
    recs = []
    if threat_level in ["HIGH", "CRITICAL"]:
        recs.append("Do not share personal information with this entity")
        recs.append("Report to platform trust & safety team")
        recs.append("Document all interactions for potential legal action")
    if any(s["name"] == "domain" and s["score"] > 50 for s in signals):
        recs.append("Verify domain registration independently before proceeding")
        recs.append("Check SSL certificate validity and issuer")
    if any(s["name"] == "linguistic" and s["score"] > 50 for s in signals):
        recs.append("Content shows strong AI-generation markers — verify source")
        recs.append("Cross-reference claims with established news sources")
    if not recs:
        recs.append("Continue monitoring — no immediate action required")
    return recs


async def scan_url(url: str, deep: bool = False) -> Dict:
    """Scan a URL — scrape, analyze content, check domain"""
    start = time.time()
    scan_id = str(uuid.uuid4())
    signals = []

    # 1. URL reputation check
    url_rep = await check_url_reputation(url)
    url_score = url_rep.get("base_risk_score", 0)
    signals.append({
        "name": "url_reputation",
        "score": url_score,
        "confidence": 0.8,
        "reasons": url_rep.get("suspicion_flags", ["URL structure appears normal"]) or ["URL structure appears normal"],
        "raw_data": url_rep,
    })

    # 2. Domain intelligence
    domain = url_rep.get("domain", "")
    domain_data = {}
    if domain:
        domain_data = await analyze_domain(domain)
        dom_flags = domain_data.get("suspicion_flags", [])
        dom_score = min(len(dom_flags) * 20, 100)
        signals.append({
            "name": "domain",
            "score": dom_score,
            "confidence": 0.85,
            "reasons": dom_flags or ["Domain appears legitimate"],
            "raw_data": {k: v for k, v in domain_data.items() if k != "ip_reputations"},
        })

    # 3. Content scraping + analysis
    content_data = {}
    content_analysis = {}
    if deep or True:  # Always scrape for URL scans
        content_data = await scrape_url(url) or {}
        if content_data.get("main_text"):
            content_analysis = analyze_text(content_data["main_text"])
            ling_score = content_analysis.get("ai_probability", 0) * 100
            manip = content_analysis.get("manipulation_indicators", [])
            ling_score = min(ling_score + len(manip) * 10, 100)
            signals.append({
                "name": "linguistic",
                "score": round(ling_score, 1),
                "confidence": 0.75,
                "reasons": content_analysis.get("linguistic_anomalies", []) + manip or ["No linguistic anomalies"],
                "raw_data": content_analysis,
            })

    # 4. Network graph
    graph_data = build_entity_graph(
        root_entity=domain or url,
        associated_domains=content_data.get("external_links", [])[:5],
        associated_ips=domain_data.get("ip_addresses", []),
        platform_presence={},
        linked_entities=[],
    )

    threat_score = calculate_threat_score(signals)
    threat_level = get_threat_level(threat_score)
    entity_type = get_entity_type(signals, "url")

    all_reasons = [r for s in signals for r in s.get("reasons", [])
                   if "appears normal" not in r and "appears legitimate" not in r
                   and "No linguistic" not in r and "No strong" not in r]

    return {
        "scan_id": scan_id,
        "input": url,
        "scan_type": "url",
        "threat_score": threat_score,
        "threat_level": threat_level,
        "entity_type": entity_type,
        "signals": signals,
        "summary": f"Detected {len(all_reasons)} suspicious indicators. Classified as {entity_type}." if all_reasons
                   else "No significant threats detected in this URL.",
        "domain_intel": domain_data or None,
        "content_analysis": content_analysis or None,
        "osint": {
            "platform_presence": {},
            "search_results_count": 0,
            "first_seen": domain_data.get("creation_date"),
            "associated_domains": content_data.get("external_links", [])[:5],
            "associated_ips": domain_data.get("ip_addresses", []),
            "data_breach_found": False,
            "reputation_score": 1.0 - (threat_score / 100),
        },
        "network_graph": graph_data,
        "recommendations": generate_recommendations(signals, threat_level),
        "scanned_at": datetime.utcnow().isoformat(),
        "scan_duration_ms": int((time.time() - start) * 1000),
    }


async def scan_text(text: str) -> Dict:
    """Analyze text for AI generation, manipulation, threats"""
    start = time.time()
    scan_id = str(uuid.uuid4())

    analysis = analyze_text(text)
    ling_score = analysis.get("ai_probability", 0) * 100
    manip = analysis.get("manipulation_indicators", [])
    ling_score = min(ling_score + len(manip) * 10, 100)

    signals = [{
        "name": "linguistic",
        "score": round(ling_score, 1),
        "confidence": 0.80,
        "reasons": analysis.get("linguistic_anomalies", []) + manip or ["No anomalies detected"],
        "raw_data": analysis,
    }]

    threat_score = ling_score
    threat_level = get_threat_level(threat_score)
    entity_type = "AI_AGENT" if ling_score > 70 else "SYNTHETIC_PERSONA" if ling_score > 40 else "UNKNOWN"

    return {
        "scan_id": scan_id,
        "input": text[:100] + "..." if len(text) > 100 else text,
        "scan_type": "text",
        "threat_score": threat_score,
        "threat_level": threat_level,
        "entity_type": entity_type,
        "signals": signals,
        "summary": f"AI generation probability: {analysis.get('ai_probability', 0)*100:.0f}%. {len(manip)} manipulation pattern(s) detected.",
        "domain_intel": None,
        "content_analysis": analysis,
        "osint": None,
        "network_graph": None,
        "recommendations": generate_recommendations(signals, threat_level),
        "scanned_at": datetime.utcnow().isoformat(),
        "scan_duration_ms": int((time.time() - start) * 1000),
    }


async def scan_domain(domain: str) -> Dict:
    """Full domain intelligence scan"""
    start = time.time()
    scan_id = str(uuid.uuid4())

    domain_data = await analyze_domain(domain)
    flags = domain_data.get("suspicion_flags", [])
    dom_score = min(len(flags) * 20, 100)

    signals = [{
        "name": "domain",
        "score": dom_score,
        "confidence": 0.85,
        "reasons": flags or ["Domain appears legitimate"],
        "raw_data": {k: v for k, v in domain_data.items() if k != "ip_reputations"},
    }]

    graph_data = build_entity_graph(
        root_entity=domain,
        associated_ips=domain_data.get("ip_addresses", []),
    )

    threat_score = dom_score
    threat_level = get_threat_level(threat_score)

    return {
        "scan_id": scan_id,
        "input": domain,
        "scan_type": "domain",
        "threat_score": threat_score,
        "threat_level": threat_level,
        "entity_type": "BOT" if threat_score > 50 else "UNKNOWN",
        "signals": signals,
        "summary": f"{len(flags)} suspicious domain indicators found." if flags else "Domain appears legitimate.",
        "domain_intel": domain_data,
        "content_analysis": None,
        "osint": {
            "platform_presence": {},
            "search_results_count": 0,
            "first_seen": domain_data.get("creation_date"),
            "associated_domains": [],
            "associated_ips": domain_data.get("ip_addresses", []),
            "data_breach_found": False,
            "reputation_score": 1.0 - (threat_score / 100),
        },
        "network_graph": graph_data,
        "recommendations": generate_recommendations(signals, threat_level),
        "scanned_at": datetime.utcnow().isoformat(),
        "scan_duration_ms": int((time.time() - start) * 1000),
    }
