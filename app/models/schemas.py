from pydantic import BaseModel
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

class ScanRequest(BaseModel):
    input: str
    scan_type: ScanType
    deep_scan: bool = False

class DetectionSignal(BaseModel):
    name: str
    score: float
    confidence: float
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
    scan_type: str
    threat_score: float
    threat_level: str
    entity_type: str
    signals: List[Dict[str, Any]]
    summary: str
    domain_intel: Optional[Dict[str, Any]] = None
    content_analysis: Optional[Dict[str, Any]] = None
    osint: Optional[Dict[str, Any]] = None
    network_graph: Optional[Dict[str, Any]] = None
    recommendations: List[str] = []
    scanned_at: str = ""
    scan_duration_ms: Optional[int] = None
