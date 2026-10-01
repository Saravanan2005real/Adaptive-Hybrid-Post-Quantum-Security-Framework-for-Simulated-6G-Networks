from enum import Enum
from dataclasses import dataclass
from typing import List

class RiskLevel(Enum):
    LOW = "LOW"           # 0 <= score < 25
    MEDIUM = "MEDIUM"     # 25 <= score < 50
    HIGH = "HIGH"         # 50 <= score < 75
    CRITICAL = "CRITICAL" # 75 <= score <= 100

class RiskEventType(Enum):
    RISK_ASSESSMENT_CREATED = "RISK_ASSESSMENT_CREATED"
    RISK_LEVEL_CHANGED = "RISK_LEVEL_CHANGED"

@dataclass
class RiskFactor:
    name: str
    contribution: float
    evidence: str

@dataclass
class RiskAssessment:
    entity_id: str
    risk_score: float
    risk_level: RiskLevel
    factors: List[RiskFactor]
    timestamp: int
