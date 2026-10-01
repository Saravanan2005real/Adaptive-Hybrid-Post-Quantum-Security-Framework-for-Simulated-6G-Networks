from typing import List, Any
from src.security.environment.models import SecurityContext
from src.security.environment.telemetry import TelemetryRecord
from src.security.risk.models import RiskLevel, RiskFactor, RiskAssessment
from src.security.risk.factors import (
    evaluate_operational_state,
    evaluate_encryption_state,
    evaluate_session_state,
    evaluate_security_mode,
    evaluate_authentication_history
)

def determine_risk_level(score: float) -> RiskLevel:
    if score < 0.0 or score > 100.0:
        raise ValueError(f"Score {score} out of bounds")
    
    if score < 25.0:
        return RiskLevel.LOW
    elif score < 50.0:
        return RiskLevel.MEDIUM
    elif score < 75.0:
        return RiskLevel.HIGH
    else:
        return RiskLevel.CRITICAL

def calculate_entity_risk(entity: Any, entity_id: str, current_tick: int) -> RiskAssessment:
    f_op = evaluate_operational_state(entity)
    
    factors = [f for f in [f_op] if f.contribution > 0.0]
    total_score = sum(f.contribution for f in factors)
    clamped_score = max(0.0, min(100.0, total_score))
    
    return RiskAssessment(
        entity_id=entity_id,
        risk_score=clamped_score,
        risk_level=determine_risk_level(clamped_score),
        factors=factors,
        timestamp=current_tick
    )

def calculate_context_risk(context: SecurityContext, context_id: str, telemetry: List[TelemetryRecord], current_tick: int) -> RiskAssessment:
    if not isinstance(context, SecurityContext):
        raise ValueError("Invalid context type provided for risk evaluation")
        
    f_enc = evaluate_encryption_state(context)
    f_ses = evaluate_session_state(context)
    f_mod = evaluate_security_mode(context)
    f_auth = evaluate_authentication_history(telemetry, context_id)
    
    all_factors = [f_enc, f_ses, f_mod, f_auth]
    factors = [f for f in all_factors if f.contribution > 0.0]
    
    total_score = sum(f.contribution for f in factors)
    clamped_score = max(0.0, min(100.0, total_score))
    
    return RiskAssessment(
        entity_id=context_id,
        risk_score=clamped_score,
        risk_level=determine_risk_level(clamped_score),
        factors=factors,
        timestamp=current_tick
    )
