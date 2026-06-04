import re
import math
from typing import List, Dict, Tuple
from collections import Counter

LLM_FILLERS = [
    r"\bit is worth noting\b", r"\bfurthermore\b", r"\bin conclusion\b",
    r"\bit is important to\b", r"\bof course\b", r"\bcertainly\b",
    r"\babsolutely\b", r"\bgreat question\b", r"\bI understand\b",
    r"\bas an AI\b", r"\bas a language model\b", r"\bI cannot\b",
    r"\bI'd be happy to\b", r"\bdelve\b", r"\bcomprehensive\b",
    r"\btailored\b", r"\bultimately\b", r"\bnevertheless\b",
    r"\bnotwithstanding\b", r"\bin summary\b", r"\bto summarize\b",
    r"\bin essence\b", r"\bmoreover\b",
]

MANIPULATION_PATTERNS = [
    r"\bevery(one|body) knows\b", r"\bit's obvious\b", r"\bclearly\b",
    r"\bundeniably\b", r"\bwithout doubt\b", r"\bproven fact\b",
    r"\bscientists (say|agree|confirm)\b", r"\bexperts (warn|say|confirm)\b",
    r"\bpeople are saying\b", r"\bmany believe\b", r"\bsome say\b",
    r"\bthey don't want you to know\b", r"\bwake up\b", r"\bsheeple\b",
    r"\bdeep state\b", r"\bplandemic\b", r"\bgreat reset\b",
]

def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = Counter(text.lower())
    total = len(text)
    return -sum((c/total) * math.log2(c/total) for c in freq.values())

def calculate_burstiness(sentences: List[str]) -> float:
    if len(sentences) < 3:
        return 0.0
    lengths = [len(s.split()) for s in sentences if s.strip()]
    if not lengths:
        return 0.0
    mean = sum(lengths) / len(lengths)
    variance = sum((l - mean) ** 2 for l in lengths) / len(lengths)
    std = variance ** 0.5
    return std / mean if mean > 0 else 0

def detect_ai_generated(text: str) -> Tuple[bool, float, List[str]]:
    if not text or len(text) < 50:
        return False, 0.0, ["Text too short for reliable analysis"]

    reasons = []
    score = 0.0
    sentences = re.split(r'[.!?]+', text)
    sentences = [s.strip() for s in sentences if len(s.strip()) > 5]
    words = text.split()

    if not words:
        return False, 0.0, ["No words found"]

    filler_hits = [p for p in LLM_FILLERS if re.search(p, text, re.IGNORECASE)]
    if len(filler_hits) >= 3:
        score += 0.30
        reasons.append(f"Contains {len(filler_hits)} LLM-typical phrases")
    elif len(filler_hits) >= 1:
        score += 0.10
        reasons.append(f"Contains {len(filler_hits)} LLM-typical phrase(s)")

    unique_words = set(w.lower().strip('.,!?;:') for w in words)
    ttr = len(unique_words) / len(words)
    if ttr < 0.45 and len(words) > 30:
        score += 0.20
        reasons.append(f"Low lexical diversity (TTR: {ttr:.2f})")
    elif ttr < 0.55 and len(words) > 50:
        score += 0.10
        reasons.append(f"Below-average lexical diversity (TTR: {ttr:.2f})")

    burstiness = calculate_burstiness(sentences)
    if burstiness < 0.25 and len(sentences) > 4:
        score += 0.20
        reasons.append(f"Uniform sentence lengths (burstiness: {burstiness:.2f})")

    contractions = len(re.findall(r"\b\w+n't\b|\b(I'm|I've|I'd|you're|we're|they're|can't|won't|don't)\b", text))
    hesitations = len(re.findall(r'\b(um|uh|hmm|well,|you know|I mean|like,)\b', text, re.IGNORECASE))
    if contractions == 0 and hesitations == 0 and len(words) > 50:
        score += 0.15
        reasons.append("No contractions or hesitations — overly formal")

    entropy = calculate_entropy(text)
    if entropy < 3.5:
        score += 0.15
        reasons.append(f"Low character entropy ({entropy:.2f})")

    if sentences:
        avg_len = sum(len(s.split()) for s in sentences) / len(sentences)
        if 17 <= avg_len <= 23 and len(sentences) > 4:
            score += 0.10
            reasons.append(f"Average sentence length ({avg_len:.1f} words) in LLM-typical range")

    probability = min(score, 0.98)
    is_ai = probability >= 0.50
    if not reasons:
        reasons.append("No strong AI-generation indicators detected")

    return is_ai, probability, reasons


def detect_manipulation(text: str) -> List[str]:
    found = []
    for pattern in MANIPULATION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            clean = re.sub(r'\\b|\(|\)', '', pattern)
            found.append(f"Manipulation pattern detected: '{clean}'")
    return found


def extract_topics(text: str) -> List[str]:
    stop_words = {
        'the','a','an','is','are','was','were','be','been','have','has',
        'had','do','does','did','will','would','could','should','may','might',
        'and','or','but','in','on','at','to','for','of','with','by','from',
        'this','that','these','those','it','its','they','them','their','we',
        'our','you','your','he','she','his','her','i','my','me','us'
    }
    words = re.findall(r'\b[a-zA-Z]{4,}\b', text.lower())
    freq = Counter(w for w in words if w not in stop_words)
    return [word for word, _ in freq.most_common(8)]


def detect_language(text: str) -> str:
    try:
        from langdetect import detect
        return detect(text)
    except Exception:
        return "unknown"


def analyze_text(text: str) -> Dict:
    is_ai, ai_prob, ai_reasons = detect_ai_generated(text)
    manipulation = detect_manipulation(text)
    topics = extract_topics(text)
    lang = detect_language(text)

    sentences = re.split(r'[.!?]+', text)
    sentences = [s for s in sentences if s.strip()]
    words = text.split()
    syllables = sum(max(1, len(re.findall(r'[aeiouAEIOU]', w))) for w in words)
    if len(sentences) > 0 and len(words) > 0:
        fk = 206.835 - 1.015*(len(words)/len(sentences)) - 84.6*(syllables/len(words))
        readability = round(max(0, min(100, fk)), 1)
    else:
        readability = None

    return {
        "is_ai_generated": is_ai,
        "ai_probability": round(ai_prob, 3),
        "language": lang,
        "sentiment": None,
        "key_topics": topics,
        "manipulation_indicators": manipulation,
        "linguistic_anomalies": ai_reasons,
        "readability_score": readability,
    }
