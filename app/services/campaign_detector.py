import hashlib
import json
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple
from collections import defaultdict


def compute_text_similarity(text1: str, text2: str) -> float:
    """Simple Jaccard similarity between two texts"""
    if not text1 or not text2:
        return 0.0
    words1 = set(text1.lower().split())
    words2 = set(text2.lower().split())
    if not words1 or not words2:
        return 0.0
    intersection = words1 & words2
    union = words1 | words2
    return len(intersection) / len(union)


def detect_coordination(entities: List[Dict]) -> Tuple[float, List[str]]:
    """
    Detect coordination patterns among a list of entities.
    Returns (coordination_score 0-1, list of evidence strings)
    """
    if len(entities) < 2:
        return 0.0, []

    evidence = []
    score = 0.0

    # 1. Shared IP addresses
    ip_map = defaultdict(list)
    for e in entities:
        for ip in e.get("ip_addresses", []):
            ip_map[ip].append(e.get("entity_input", "unknown"))

    shared_ips = {ip: ents for ip, ents in ip_map.items() if len(ents) > 1}
    if shared_ips:
        score += 0.35
        for ip, ents in list(shared_ips.items())[:3]:
            evidence.append(f"Shared infrastructure: {len(ents)} entities on IP {ip}")

    # 2. Similar threat scores (within 10 points)
    scores = [e.get("threat_score", 0) for e in entities]
    if len(scores) >= 3:
        avg = sum(scores) / len(scores)
        variance = sum((s - avg) ** 2 for s in scores) / len(scores)
        if variance < 100:  # Low variance = similar scores
            score += 0.20
            evidence.append(f"Uniform threat scores (avg: {avg:.1f}, variance: {variance:.1f}) — suggests same operator")

    # 3. Same entity type across most entities
    types = [e.get("entity_type", "UNKNOWN") for e in entities]
    dominant_type = max(set(types), key=types.count)
    type_ratio = types.count(dominant_type) / len(types)
    if type_ratio > 0.7 and len(entities) >= 3:
        score += 0.15
        evidence.append(f"{int(type_ratio*100)}% of entities classified as {dominant_type}")

    # 4. Text similarity in signals
    all_reasons = []
    for e in entities:
        for sig in e.get("signals", []):
            all_reasons.extend(sig.get("reasons", []))

    if all_reasons:
        reason_freq = defaultdict(int)
        for r in all_reasons:
            reason_freq[r] += 1
        repeated = {r: c for r, c in reason_freq.items() if c > 1 and "No " not in r}
        if repeated:
            score += 0.20
            top = sorted(repeated.items(), key=lambda x: -x[1])[:2]
            for reason, count in top:
                evidence.append(f"Repeated signal across {count} entities: '{reason[:80]}'")

    # 5. Platform overlap
    platform_map = defaultdict(int)
    for e in entities:
        for p in e.get("platforms", []):
            platform_map[p] += 1
    shared_platforms = {p: c for p, c in platform_map.items() if c > 1}
    if shared_platforms:
        score += 0.10
        evidence.append(f"Platform overlap detected: {list(shared_platforms.keys())}")

    return min(score, 1.0), evidence


def detect_infrastructure_overlap(entities: List[Dict]) -> float:
    """Calculate what % of entities share infrastructure"""
    if len(entities) < 2:
        return 0.0

    all_ips = [set(e.get("ip_addresses", [])) for e in entities]
    overlapping = 0
    for i, ips1 in enumerate(all_ips):
        for ips2 in all_ips[i+1:]:
            if ips1 & ips2:
                overlapping += 1
                break

    return overlapping / len(entities)


def infer_tactics(entities: List[Dict], target: Optional[str] = None) -> List[str]:
    """Infer attack tactics from entity signals"""
    tactics = set()

    for e in entities:
        for sig in e.get("signals", []):
            reasons = sig.get("reasons", [])
            for r in reasons:
                r_lower = r.lower()
                if "ai-generated" in r_lower or "llm" in r_lower:
                    tactics.add("Synthetic Content Generation")
                if "coordination" in r_lower or "network" in r_lower:
                    tactics.add("Coordinated Inauthentic Behavior")
                if "bot" in r_lower or "automated" in r_lower:
                    tactics.add("Automated Amplification")
                if "phishing" in r_lower or "typosquat" in r_lower:
                    tactics.add("Phishing / Identity Spoofing")
                if "manipulation" in r_lower or "propaganda" in r_lower:
                    tactics.add("Narrative Manipulation")
                if "vpn" in r_lower or "proxy" in r_lower:
                    tactics.add("Infrastructure Obfuscation")

    return list(tactics)


def generate_campaign_summary(
    name: str,
    entities: List[Dict],
    target: Optional[str],
    coordination_score: float,
    tactics: List[str],
    evidence: List[str]
) -> str:
    """Generate human-readable campaign summary"""
    entity_count = len(entities)
    avg_threat = sum(e.get("threat_score", 0) for e in entities) / max(entity_count, 1)

    summary = f"Campaign '{name}' involves {entity_count} identified entity/entities"

    if target:
        summary += f" targeting '{target}'"

    summary += f". Average threat score: {avg_threat:.1f}/100."

    if coordination_score > 0.6:
        summary += f" HIGH coordination detected ({int(coordination_score*100)}%) — strong indicators of organized operation."
    elif coordination_score > 0.3:
        summary += f" Moderate coordination detected ({int(coordination_score*100)}%)."

    if tactics:
        summary += f" Tactics identified: {', '.join(tactics[:3])}."

    if evidence:
        summary += f" Key evidence: {evidence[0]}"

    return summary


def generate_evidence_hash(campaign_data: Dict) -> str:
    """Generate SHA-256 hash of campaign evidence for tamper detection"""
    canonical = json.dumps(campaign_data, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def assess_campaign_threat_level(
    entity_count: int,
    coordination_score: float,
    avg_threat_score: float,
    tactics: List[str]
) -> str:
    """Determine overall campaign threat level"""
    score = 0

    if entity_count >= 10:
        score += 3
    elif entity_count >= 5:
        score += 2
    elif entity_count >= 2:
        score += 1

    if coordination_score >= 0.7:
        score += 3
    elif coordination_score >= 0.4:
        score += 2
    elif coordination_score >= 0.2:
        score += 1

    if avg_threat_score >= 75:
        score += 3
    elif avg_threat_score >= 50:
        score += 2
    elif avg_threat_score >= 25:
        score += 1

    high_risk_tactics = {"Coordinated Inauthentic Behavior", "Phishing / Identity Spoofing", "Narrative Manipulation"}
    if any(t in high_risk_tactics for t in tactics):
        score += 2

    if score >= 8:
        return "CRITICAL"
    if score >= 5:
        return "HIGH"
    if score >= 3:
        return "MEDIUM"
    return "LOW"
