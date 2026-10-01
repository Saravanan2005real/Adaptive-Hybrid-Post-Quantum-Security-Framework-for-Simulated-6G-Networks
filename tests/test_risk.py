import pytest
from src.security.risk.models import RiskLevel, RiskAssessment, RiskEventType, RiskFactor
from src.security.risk.factors import (
    evaluate_operational_state, evaluate_encryption_state, 
    evaluate_session_state, evaluate_security_mode, evaluate_authentication_history,
    WEIGHT_COMPROMISED, WEIGHT_DEGRADED, WEIGHT_OFFLINE, 
    WEIGHT_ENCRYPTION_DISABLED, WEIGHT_NO_SESSION, 
    WEIGHT_AUTH_FAILURE_BASE, WEIGHT_AUTH_FAILURE_MAX,
    WEIGHT_MODE_CLASSICAL, WEIGHT_MODE_PQC, WEIGHT_MODE_HYBRID
)
from src.security.risk.scorer import determine_risk_level, calculate_entity_risk, calculate_context_risk
from src.security.risk.manager import RiskManager
from src.security.environment.manager import EnvironmentManager
from src.security.environment.models import (
    DeviceContext, CoreContext, EdgeContext,
    SecurityMode, AuthStatus, OperationalState, EnvironmentEventType
)
from src.security.environment.telemetry import TelemetryRecord
from src.events import EventLogger, EventType

def setup_env():
    mgr = EnvironmentManager()
    mgr.register_core(CoreContext("core_1", OperationalState.ONLINE, [SecurityMode.CLASSICAL, SecurityMode.PQC, SecurityMode.HYBRID]))
    mgr.register_edge(EdgeContext("edge_1", OperationalState.ONLINE, [SecurityMode.CLASSICAL, SecurityMode.PQC, SecurityMode.HYBRID], "core_1"))
    mgr.register_device(DeviceContext("dev_1", "iot", OperationalState.ONLINE, [SecurityMode.CLASSICAL, SecurityMode.PQC, SecurityMode.HYBRID], [], [], "edge_1"))
    return mgr

def get_context(mgr, mode=SecurityMode.HYBRID):
    return mgr.create_communication_context("ctx_1", "dev_1", "core_1", mode)

# 1. LOW risk calculation
def test_low_risk_calculation():
    assert determine_risk_level(0.0) == RiskLevel.LOW
    assert determine_risk_level(24.9) == RiskLevel.LOW

# 2. MEDIUM risk calculation
def test_medium_risk_calculation():
    assert determine_risk_level(25.0) == RiskLevel.MEDIUM
    assert determine_risk_level(49.9) == RiskLevel.MEDIUM

# 3. HIGH risk calculation
def test_high_risk_calculation():
    assert determine_risk_level(50.0) == RiskLevel.HIGH
    assert determine_risk_level(74.9) == RiskLevel.HIGH

# 4. CRITICAL risk calculation
def test_critical_risk_calculation():
    assert determine_risk_level(75.0) == RiskLevel.CRITICAL
    assert determine_risk_level(100.0) == RiskLevel.CRITICAL

# 5. threshold boundary values
def test_threshold_boundary_values():
    assert determine_risk_level(25.0) == RiskLevel.MEDIUM
    assert determine_risk_level(50.0) == RiskLevel.HIGH
    assert determine_risk_level(75.0) == RiskLevel.CRITICAL

# 6. score clamping
def test_score_clamping():
    mgr = setup_env()
    mgr.update_entity_state("dev_1", OperationalState.COMPROMISED) # +80
    ctx = get_context(mgr, SecurityMode.CLASSICAL) # +10
    mgr.update_security_context("ctx_1", encryption_active=False) # +40
    
    # 80 + 10 + 40 = 130, should clamp to 100
    risk = calculate_context_risk(ctx.security, "ctx_1", [], 1)
    assert risk.risk_score <= 100.0

    risk_entity = calculate_entity_risk(mgr.get_entity("dev_1"), "dev_1", 1)
    assert risk_entity.risk_score == 80.0

# 7. authentication failure contribution
def test_auth_failure_contribution():
    records = [TelemetryRecord(1, 0.0, EnvironmentEventType.AUTHENTICATION_FAILED.value, "ctx_1", "dev_1", {})]
    factor = evaluate_authentication_history(records, "ctx_1")
    assert factor.contribution == WEIGHT_AUTH_FAILURE_BASE

# 8. repeated authentication failures max clamp
def test_repeated_auth_failures_clamp():
    records = [TelemetryRecord(i, float(i), EnvironmentEventType.AUTHENTICATION_FAILED.value, "ctx_1", "dev_1", {}) for i in range(10)]
    factor = evaluate_authentication_history(records, "ctx_1")
    assert factor.contribution == WEIGHT_AUTH_FAILURE_MAX

# 9. compromised entity contribution
def test_compromised_entity_contribution():
    mgr = setup_env()
    mgr.update_entity_state("dev_1", OperationalState.COMPROMISED)
    factor = evaluate_operational_state(mgr.get_entity("dev_1"))
    assert factor.contribution == WEIGHT_COMPROMISED

# 10. operational state contribution
def test_operational_state_contribution():
    mgr = setup_env()
    mgr.update_entity_state("dev_1", OperationalState.DEGRADED)
    factor = evaluate_operational_state(mgr.get_entity("dev_1"))
    assert factor.contribution == WEIGHT_DEGRADED
    
    mgr.update_entity_state("dev_1", OperationalState.OFFLINE)
    factor = evaluate_operational_state(mgr.get_entity("dev_1"))
    assert factor.contribution == WEIGHT_OFFLINE

# 11. encryption inactive contribution
def test_encryption_inactive_contribution():
    mgr = setup_env()
    ctx = get_context(mgr)
    factor = evaluate_encryption_state(ctx.security)
    assert factor.contribution == WEIGHT_ENCRYPTION_DISABLED

# 12. missing session contribution
def test_missing_session_contribution():
    mgr = setup_env()
    ctx = get_context(mgr)
    factor = evaluate_session_state(ctx.security)
    assert factor.contribution == WEIGHT_NO_SESSION

# 13. security mode representation
def test_security_mode_representation():
    mgr = setup_env()
    ctx = get_context(mgr, SecurityMode.CLASSICAL)
    assert evaluate_security_mode(ctx.security).contribution == WEIGHT_MODE_CLASSICAL
    
    ctx2 = mgr.create_communication_context("ctx_2", "dev_1", "core_1", SecurityMode.PQC)
    assert evaluate_security_mode(ctx2.security).contribution == WEIGHT_MODE_PQC
    
    ctx3 = mgr.create_communication_context("ctx_3", "dev_1", "core_1", SecurityMode.HYBRID)
    assert evaluate_security_mode(ctx3.security).contribution == WEIGHT_MODE_HYBRID

# 14. telemetry contribution
def test_telemetry_contribution():
    mgr = setup_env()
    ctx = get_context(mgr)
    mgr.telemetry.record(1, EnvironmentEventType.AUTHENTICATION_FAILED.value, "ctx_1", "dev_1", {})
    r = calculate_context_risk(ctx.security, "ctx_1", mgr.telemetry.records, 1)
    assert any(f.name == "authentication_failures" and f.contribution > 0 for f in r.factors)

# 15. unknown entity rejection
def test_unknown_entity_rejection():
    mgr = setup_env()
    rm = RiskManager(mgr)
    with pytest.raises(ValueError, match="does not exist in environment"):
        rm.evaluate_entity("unknown_entity")
    with pytest.raises(ValueError, match="does not exist in environment"):
        rm.evaluate_context("unknown_ctx")

# 16. invalid input rejection
def test_invalid_input_rejection():
    with pytest.raises(ValueError, match="out of bounds"):
        determine_risk_level(-1.0)
    with pytest.raises(ValueError, match="out of bounds"):
        determine_risk_level(101.0)

# 17. deterministic repeated evaluation
def test_deterministic_repeated_evaluation():
    mgr = setup_env()
    rm = RiskManager(mgr)
    get_context(mgr)
    r1 = rm.evaluate_context("ctx_1")
    r2 = rm.evaluate_context("ctx_1")
    assert r1.risk_score == r2.risk_score
    assert r1.risk_level == r2.risk_level

# 18. factor evidence generation
def test_factor_evidence_generation():
    mgr = setup_env()
    rm = RiskManager(mgr)
    get_context(mgr)
    r = rm.evaluate_context("ctx_1")
    for factor in r.factors:
        assert isinstance(factor.evidence, str)
        assert len(factor.evidence) > 0

# 19. risk history
def test_risk_history():
    mgr = setup_env()
    rm = RiskManager(mgr)
    rm.evaluate_entity("dev_1")
    rm.evaluate_entity("dev_1")
    assert len(rm.history) == 2

# 20. risk history immutability
def test_risk_history_immutability():
    mgr = setup_env()
    rm = RiskManager(mgr)
    r1 = rm.evaluate_entity("dev_1")
    
    # Mutate external object
    r1.risk_score = 999.9
    r1.factors.append(RiskFactor("fake", 10.0, "fake"))
    
    assert rm.history[0].risk_score != 999.9
    assert len(rm.history[0].factors) == 0 # Should have no factors originally

# 21. no secret/key leakage (implied by design of evaluate functions extracting enums/bools only)
def test_no_secret_leakage():
    mgr = setup_env()
    rm = RiskManager(mgr)
    ctx = get_context(mgr)
    mgr.update_security_context("ctx_1", session_id="ses_123")
    r = rm.evaluate_context("ctx_1")
    for factor in r.factors:
        assert "ses_123" not in factor.evidence

# 22. no mutation of Step 7 environment
def test_no_mutation_of_environment():
    mgr = setup_env()
    rm = RiskManager(mgr)
    ctx = get_context(mgr)
    rm.evaluate_context("ctx_1")
    assert mgr.comm_contexts["ctx_1"].security.encryption_active is False
    assert mgr.comm_contexts["ctx_1"].security.session_id is None

# 23. no mutation of Step 7 telemetry
def test_no_mutation_of_telemetry():
    mgr = setup_env()
    rm = RiskManager(mgr)
    ctx = get_context(mgr)
    mgr.telemetry.record(1, EnvironmentEventType.AUTHENTICATION_FAILED.value, "ctx_1", "dev_1", {})
    count_before = len(mgr.telemetry.records)
    rm.evaluate_context("ctx_1")
    assert len(mgr.telemetry.records) == count_before

# 24. event logging
def test_event_logging():
    logger = EventLogger()
    mgr = setup_env()
    rm = RiskManager(mgr, logger)
    ctx = get_context(mgr)
    rm.evaluate_context("ctx_1")
    
    logs = [log for log in logger.get_events() if log["event_type"] == EventType.RISK_ASSESSMENT_CREATED.value]
    assert len(logs) == 1

# 25. Risk levels properly emit RISK_LEVEL_CHANGED
def test_risk_level_changed_event():
    logger = EventLogger()
    mgr = setup_env()
    rm = RiskManager(mgr, logger)
    ctx = get_context(mgr)
    
    rm.evaluate_context("ctx_1")
    mgr.update_security_context("ctx_1", encryption_active=True, session_id="ses_123")
    rm.evaluate_context("ctx_1")
    
    logs = [log for log in logger.get_events() if log["event_type"] == EventType.RISK_LEVEL_CHANGED.value]
    assert len(logs) > 0
