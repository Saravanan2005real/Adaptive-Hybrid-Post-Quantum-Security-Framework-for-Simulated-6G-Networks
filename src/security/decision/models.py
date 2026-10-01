from dataclasses import dataclass
from typing import Optional
from src.security.risk.models import RiskLevel
from src.security.environment.models import SecurityMode

@dataclass
class DecisionResult:
    entity_id: str
    context_id: str
    risk_score: float
    risk_level: RiskLevel
    current_security_mode: SecurityMode
    recommended_security_mode: SecurityMode
    decision_reason: str
    policy_rule: str
    timestamp: int
    mode_changed: bool
    requires_transition: bool
