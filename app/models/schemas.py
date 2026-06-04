from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Dict, Any
from enum import Enum
from datetime import datetime

class ThreatLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class EntityType(str, Enum):
    HUMAN = "HUMAN"
    BOT = "BOT"
    HYBRID = "HYBRID"
    SYNTHETIC_PERSONA = "SYNTHETIC_PERSONA"
    AI_AGENT = "AI_AGENT"
    UNKNOWN = "UNKNOWN"

class ScanType(str, Enum):
    URL = "url"
    USERNAME = "username"
    TEXT = "text"
    DOMAIN = "domain"
    EMAIL = "email"
    IP = "ip"

# --- Request Models ---

class ScanRequest(BaseModel):
    input: str
    scan_type: ScanType
    deep_scan: bool = False

class TextAnalysisRequest(BaseModel):
    text: str
    context: Optional[str] = None

class AgentDetectionRequest(BaseModel):
    content: str
    content_type: str = "text"  # text, email, chat, api_log
    metadata: Optional[Dict[str, Any]] = None

# --- Signal Models ---

class DetectionSignal(BaseModel):
    name: str
    score: float  # 0-100
    confidence: float  # 0-1
    reasons: List[str]
    raw_data: Optional[Dict[str, Any]] = None

class NetworkNode(BaseModel):
    id: str
    label: str
    type: str
    threat_score: float
    platform: Optional[str] = None

class NetworkEdge(BaseModel):
    source: str
    target: str
    relationship: str
    weight: float = 1.0

class NetworkGraph(BaseModel):
    nodes: List[NetworkNode]
    edges: List[NetworkEdge]

# --- Result Models ---

class DomainIntelligence(BaseModel):
    domain: str
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    country: Optional[str] = None
    nameservers: List[str] = []
    ip_addresses: List[str] = []
    is_privacy_protected: bool = False
    age_days: Optional[int] = None
    suspicion_flags: List[str] = []

class ContentAnalysis(BaseModel):
    is_ai_generated: bool
    ai_probability: float
    language: Optional[str] = None
    sentiment: Optional[str] = None
    key_topics: List[str] = []
    manipulation_indicators: List[str] = []
    linguistic_anomalies: List[str] = []
    readability_score: Optional[float] = None

class OpenSourceIntel(BaseModel):
    platform_presence: Dict[str, bool] = {}
    search_results_count: int = 0
    first_seen: Optional[str] = None
    associated_domains: List[str] = []
    associated_ips: List[str] = []
    data_breach_found: bool = False
    reputation_score: Optional[float] = None

class ScanResult(BaseModel):
    scan_id: str
    input: str
    scan_type: ScanType
    threat_score: float
    threat_level: ThreatLevel
    entity_type: EntityType
    signals: List[DetectionSignal]
    summary: str
    domain_intel: Optional[DomainIntelligence] = None
    content_analysis: Optional[ContentAnalysis] = None
    osint: Optional[OpenSourceIntel] = None
    network_graph: Optional[NetworkGraph] = None
    recommendations: List[str] = []
    scanned_at: datetime = datetime.utcnow()
    scan_duration_ms: Optional[int] = None
