from dataclasses import dataclass
from typing import Optional
from src.security.risk.models import RiskLevel
from src.security.environment.models import SecurityMode

@dataclass(frozen=True)
class AdaptiveDecisionResult:
    timestamp: int
    context_id: str
    entity_id: Optional[str]
    rule_risk_score: float
    rule_risk_level: RiskLevel
    ml_risk_score: float
    ml_risk_level: RiskLevel
    fused_risk_score: float
    fused_risk_level: RiskLevel
    risk_disagreement: float
    current_security_mode: SecurityMode
    recommended_security_mode: SecurityMode
    transition_required: bool
    transition_applied: bool
    suppression_reason: Optional[str] = None
    
    def __post_init__(self):
        if not (0.0 <= self.rule_risk_score <= 100.0):
            raise ValueError("Rule risk score must be between 0 and 100")
        if not (0.0 <= self.ml_risk_score <= 100.0):
            raise ValueError("ML risk score must be between 0 and 100")
        if not (0.0 <= self.fused_risk_score <= 100.0):
            raise ValueError("Fused risk score must be between 0 and 100")
