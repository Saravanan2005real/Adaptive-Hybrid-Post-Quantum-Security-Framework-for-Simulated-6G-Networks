from typing import Dict, Any, List
from src.security.environment.models import (
    SecurityContext, OperationalState, SecurityMode, AuthStatus, EnvironmentEventType
)
from src.security.environment.manager import EnvironmentManager

FEATURE_NAMES = [
    "operational_state_code",
    "encryption_active",
    "session_active",
    "security_mode_code",
    "authentication_failure_count",
    "authentication_success_indicator",
    "telemetry_count",
    "authentication_failure_rate"
]

OPERATIONAL_STATE_ENCODING = {
    OperationalState.ONLINE: 0,
    OperationalState.DEGRADED: 1,
    OperationalState.OFFLINE: 2,
    OperationalState.COMPROMISED: 3
}

SECURITY_MODE_ENCODING = {
    SecurityMode.CLASSICAL: 0,
    SecurityMode.PQC: 1,
    SecurityMode.HYBRID: 2
}

def extract_features(env: EnvironmentManager, context_id: str, telemetry_window_ticks: int = 100) -> List[float]:
    """
    Extracts a deterministic feature vector from the environment for ML prediction.
    """
    if context_id not in env.comm_contexts:
        raise ValueError(f"Context {context_id} does not exist in environment")
        
    ctx = env.comm_contexts[context_id]
    entity_id = ctx.source_id
    
    if not env.entity_exists(entity_id):
        raise ValueError(f"Entity {entity_id} does not exist in environment")
        
    entity = env.get_entity(entity_id)
    security = ctx.security
    
    # 1. Operational State Code
    op_state = getattr(entity, 'operational_state', OperationalState.ONLINE)
    if op_state not in OPERATIONAL_STATE_ENCODING:
        raise ValueError(f"Invalid operational state: {op_state}")
    op_state_code = float(OPERATIONAL_STATE_ENCODING[op_state])
    
    # 2. Encryption Active
    enc_active = 1.0 if getattr(security, 'encryption_active', False) else 0.0
    
    # 3. Session Active
    sess_active = 1.0 if getattr(security, 'session_id', None) is not None else 0.0
    
    # 4. Security Mode Code
    sec_mode = getattr(security, 'security_mode', SecurityMode.CLASSICAL)
    if sec_mode not in SECURITY_MODE_ENCODING:
        raise ValueError(f"Invalid security mode: {sec_mode}")
    sec_mode_code = float(SECURITY_MODE_ENCODING[sec_mode])
    
    # Telemetry extraction
    min_tick = max(0, env.current_tick - telemetry_window_ticks)
    relevant_telemetry = [
        r for r in env.telemetry.records 
        if r.timestamp >= min_tick and r.context_id == context_id
    ]
    
    # 5. Authentication Failure Count
    auth_failures = sum(1 for r in relevant_telemetry if r.event_type == EnvironmentEventType.AUTHENTICATION_FAILED.value)
    
    # 6. Authentication Success Indicator
    auth_success = 1.0 if getattr(security, 'auth_status', AuthStatus.UNAUTHENTICATED) == AuthStatus.AUTHENTICATED else 0.0
    
    # 7. Telemetry Count
    telemetry_count = len(relevant_telemetry)
    
    # 8. Authentication Failure Rate
    auth_failure_rate = auth_failures / telemetry_count if telemetry_count > 0 else 0.0
    
    features = [
        op_state_code,
        enc_active,
        sess_active,
        sec_mode_code,
        float(auth_failures),
        auth_success,
        float(telemetry_count),
        float(auth_failure_rate)
    ]
    
    if len(features) != len(FEATURE_NAMES):
        raise RuntimeError("Feature count mismatch")
        
    return features
