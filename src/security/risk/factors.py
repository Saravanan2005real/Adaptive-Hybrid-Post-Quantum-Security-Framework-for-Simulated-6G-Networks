from typing import List, Any
from src.security.environment.models import SecurityContext, SecurityMode, OperationalState, EnvironmentEventType
from src.security.risk.models import RiskFactor
from src.security.environment.telemetry import TelemetryRecord

# Explicit Documentation of Risk Weights (Research Assumptions)
WEIGHT_COMPROMISED = 80.0
WEIGHT_DEGRADED = 30.0
WEIGHT_OFFLINE = 10.0
WEIGHT_ENCRYPTION_DISABLED = 40.0
WEIGHT_NO_SESSION = 30.0
WEIGHT_AUTH_FAILURE_BASE = 15.0
WEIGHT_AUTH_FAILURE_MAX = 45.0
WEIGHT_MODE_CLASSICAL = 10.0  # Slightly higher risk assigned to classical compared to PQC/HYBRID as a research assumption
WEIGHT_MODE_PQC = 5.0
WEIGHT_MODE_HYBRID = 0.0

def evaluate_operational_state(entity: Any) -> RiskFactor:
    if not hasattr(entity, "operational_state"):
        raise ValueError("Entity is missing operational_state")
    state = entity.operational_state
    if state == OperationalState.COMPROMISED:
        return RiskFactor("operational_state", float(WEIGHT_COMPROMISED), "Entity is explicitly compromised")
    elif state == OperationalState.DEGRADED:
        return RiskFactor("operational_state", float(WEIGHT_DEGRADED), "Entity is operating in a degraded state")
    elif state == OperationalState.OFFLINE:
        return RiskFactor("operational_state", float(WEIGHT_OFFLINE), "Entity is offline")
    return RiskFactor("operational_state", 0.0, "Entity is online and healthy")

def evaluate_encryption_state(context: SecurityContext) -> RiskFactor:
    if not hasattr(context, "encryption_active"):
        raise ValueError("Context is missing encryption_active")
    if not context.encryption_active:
        return RiskFactor("encryption_state", float(WEIGHT_ENCRYPTION_DISABLED), "Encryption is inactive")
    return RiskFactor("encryption_state", 0.0, "Encryption is active")

def evaluate_session_state(context: SecurityContext) -> RiskFactor:
    if not hasattr(context, "session_id"):
        raise ValueError("Context is missing session_id")
    if context.session_id is None:
        return RiskFactor("session_state", float(WEIGHT_NO_SESSION), "No active secure session")
    return RiskFactor("session_state", 0.0, "Active secure session established")

def evaluate_security_mode(context: SecurityContext) -> RiskFactor:
    if not hasattr(context, "security_mode"):
        raise ValueError("Context is missing security_mode")
    if context.security_mode == SecurityMode.CLASSICAL:
        return RiskFactor("security_mode", float(WEIGHT_MODE_CLASSICAL), "Classical security mode active")
    elif context.security_mode == SecurityMode.PQC:
        return RiskFactor("security_mode", float(WEIGHT_MODE_PQC), "PQC security mode active")
    elif context.security_mode == SecurityMode.HYBRID:
        return RiskFactor("security_mode", float(WEIGHT_MODE_HYBRID), "Hybrid security mode active")
    raise ValueError(f"Unknown security mode: {context.security_mode}")

def evaluate_authentication_history(records: List[TelemetryRecord], context_id: str) -> RiskFactor:
    failures = sum(1 for r in records if r.context_id == context_id and r.event_type == EnvironmentEventType.AUTHENTICATION_FAILED.value)
    
    if failures == 0:
        return RiskFactor("authentication_failures", 0.0, "No authentication failures in window")
    
    contribution = min(failures * float(WEIGHT_AUTH_FAILURE_BASE), float(WEIGHT_AUTH_FAILURE_MAX))
    return RiskFactor(
        "authentication_failures", 
        float(contribution), 
        f"{failures} authentication failure(s) in evaluation window"
    )
