import pytest
from src.security.risk.models import RiskLevel, RiskAssessment, RiskFactor
from src.security.environment.models import SecurityMode
from src.security.decision.models import DecisionResult
from src.security.decision.policy import (
    get_policy_recommendation, get_policy_rule_description, get_decision_reason
)
from src.security.decision.engine import DecisionEngine
from src.events import EventLogger, EventType
from src.security.environment.manager import EnvironmentManager
from src.security.environment.models import CoreContext, EdgeContext, DeviceContext, OperationalState
from src.security.risk.manager import RiskManager

def create_assessment(score: float, level: RiskLevel, entity_id="dev_1", ctx_id="ctx_1") -> RiskAssessment:
    return RiskAssessment(
        entity_id=entity_id,
        risk_score=score,
        risk_level=level,
        factors=[RiskFactor("fake", score, "fake")],
        timestamp=1
    )

def test_policy_low(): # 1
    assert get_policy_recommendation(RiskLevel.LOW) == SecurityMode.CLASSICAL

def test_policy_medium(): # 2
    assert get_policy_recommendation(RiskLevel.MEDIUM) == SecurityMode.PQC

def test_policy_high(): # 3
    assert get_policy_recommendation(RiskLevel.HIGH) == SecurityMode.HYBRID

def test_policy_critical(): # 4
    assert get_policy_recommendation(RiskLevel.CRITICAL) == SecurityMode.HYBRID

def test_decision_classical_low(): # 5
    engine = DecisionEngine()
    r = engine.evaluate_decision(create_assessment(10.0, RiskLevel.LOW), SecurityMode.CLASSICAL, "ctx_1")
    assert r.recommended_security_mode == SecurityMode.CLASSICAL
    assert r.requires_transition is False

def test_decision_classical_medium(): # 6
    engine = DecisionEngine()
    r = engine.evaluate_decision(create_assessment(30.0, RiskLevel.MEDIUM), SecurityMode.CLASSICAL, "ctx_1")
    assert r.recommended_security_mode == SecurityMode.PQC
    assert r.requires_transition is True

def test_decision_classical_high(): # 7
    engine = DecisionEngine()
    r = engine.evaluate_decision(create_assessment(60.0, RiskLevel.HIGH), SecurityMode.CLASSICAL, "ctx_1")
    assert r.recommended_security_mode == SecurityMode.HYBRID
    assert r.requires_transition is True

def test_decision_pqc_medium(): # 8
    engine = DecisionEngine()
    r = engine.evaluate_decision(create_assessment(30.0, RiskLevel.MEDIUM), SecurityMode.PQC, "ctx_1")
    assert r.recommended_security_mode == SecurityMode.PQC
    assert r.requires_transition is False

def test_decision_pqc_high(): # 9
    engine = DecisionEngine()
    r = engine.evaluate_decision(create_assessment(60.0, RiskLevel.HIGH), SecurityMode.PQC, "ctx_1")
    assert r.recommended_security_mode == SecurityMode.HYBRID
    assert r.requires_transition is True

def test_decision_hybrid_high(): # 10
    engine = DecisionEngine()
    r = engine.evaluate_decision(create_assessment(60.0, RiskLevel.HIGH), SecurityMode.HYBRID, "ctx_1")
    assert r.recommended_security_mode == SecurityMode.HYBRID
    assert r.requires_transition is False

def test_decision_hybrid_critical(): # 11
    engine = DecisionEngine()
    r = engine.evaluate_decision(create_assessment(90.0, RiskLevel.CRITICAL), SecurityMode.HYBRID, "ctx_1")
    assert r.recommended_security_mode == SecurityMode.HYBRID
    assert r.requires_transition is False

def test_invalid_entity_rejected(): # 12
    engine = DecisionEngine()
    with pytest.raises(ValueError, match="Missing entity_id"):
        engine.evaluate_decision(create_assessment(10.0, RiskLevel.LOW, entity_id=""), SecurityMode.CLASSICAL, "ctx_1")

def test_invalid_context_rejected(): # 13
    engine = DecisionEngine()
    with pytest.raises(ValueError, match="Missing context_id"):
        engine.evaluate_decision(create_assessment(10.0, RiskLevel.LOW), SecurityMode.CLASSICAL, "")

def test_invalid_risk_score_rejected(): # 14
    engine = DecisionEngine()
    with pytest.raises(ValueError, match="Invalid risk score"):
        engine.evaluate_decision(create_assessment(-10.0, RiskLevel.LOW), SecurityMode.CLASSICAL, "ctx_1")

def test_invalid_risk_level_rejected(): # 15
    engine = DecisionEngine()
    with pytest.raises(ValueError, match="Invalid risk level type"):
        engine.evaluate_decision(create_assessment(10.0, "NOT_AN_ENUM"), SecurityMode.CLASSICAL, "ctx_1")

def test_invalid_security_mode_rejected(): # 16
    engine = DecisionEngine()
    with pytest.raises(ValueError, match="Invalid current security mode"):
        engine.evaluate_decision(create_assessment(10.0, RiskLevel.LOW), "INVALID_MODE", "ctx_1")

def test_inconsistent_score_level_rejected(): # 17
    engine = DecisionEngine()
    with pytest.raises(ValueError, match="does not match level"):
        # 80.0 is CRITICAL, but supplying LOW
        engine.evaluate_decision(create_assessment(80.0, RiskLevel.LOW), SecurityMode.CLASSICAL, "ctx_1")

def test_decision_reason_present(): # 18
    engine = DecisionEngine()
    r = engine.evaluate_decision(create_assessment(10.0, RiskLevel.LOW), SecurityMode.CLASSICAL, "ctx_1")
    assert len(r.decision_reason) > 0

def test_policy_rule_present(): # 19
    engine = DecisionEngine()
    r = engine.evaluate_decision(create_assessment(10.0, RiskLevel.LOW), SecurityMode.CLASSICAL, "ctx_1")
    assert len(r.policy_rule) > 0

def test_decision_result_contains_risk(): # 20
    engine = DecisionEngine()
    r = engine.evaluate_decision(create_assessment(10.0, RiskLevel.LOW), SecurityMode.CLASSICAL, "ctx_1")
    assert r.risk_score == 10.0
    assert r.risk_level == RiskLevel.LOW

def test_decision_no_secret_material(): # 21
    engine = DecisionEngine()
    r = engine.evaluate_decision(create_assessment(10.0, RiskLevel.LOW), SecurityMode.CLASSICAL, "ctx_1")
    s = str(r)
    assert "secret" not in s.lower()
    assert "key" not in s.lower()

def test_decision_recorded_in_history(): # 22
    engine = DecisionEngine()
    r = engine.evaluate_decision(create_assessment(10.0, RiskLevel.LOW), SecurityMode.CLASSICAL, "ctx_1")
    assert len(engine.history) == 1

def test_history_not_corrupted_by_mutation(): # 23
    engine = DecisionEngine()
    r = engine.evaluate_decision(create_assessment(10.0, RiskLevel.LOW), SecurityMode.CLASSICAL, "ctx_1")
    r.risk_score = 999.0
    assert engine.history[0].risk_score == 10.0

def test_decision_event_generated(): # 24
    logger = EventLogger()
    engine = DecisionEngine(logger)
    engine.evaluate_decision(create_assessment(10.0, RiskLevel.LOW), SecurityMode.CLASSICAL, "ctx_1")
    logs = [log for log in logger.get_events() if log["event_type"] == EventType.SECURITY_DECISION_CREATED.value]
    assert len(logs) == 1

def test_mode_change_event_conditional(): # 25
    logger = EventLogger()
    engine = DecisionEngine(logger)
    
    # No transition
    engine.evaluate_decision(create_assessment(10.0, RiskLevel.LOW), SecurityMode.CLASSICAL, "ctx_1")
    logs = [log for log in logger.get_events() if log["event_type"] == EventType.SECURITY_MODE_CHANGE_RECOMMENDED.value]
    assert len(logs) == 0
    
    # Transition
    engine.evaluate_decision(create_assessment(60.0, RiskLevel.HIGH), SecurityMode.CLASSICAL, "ctx_1")
    logs = [log for log in logger.get_events() if log["event_type"] == EventType.SECURITY_MODE_CHANGE_RECOMMENDED.value]
    assert len(logs) == 1

def test_determinism_identical_inputs(): # 26
    engine = DecisionEngine()
    r1 = engine.evaluate_decision(create_assessment(60.0, RiskLevel.HIGH), SecurityMode.CLASSICAL, "ctx_1")
    r2 = engine.evaluate_decision(create_assessment(60.0, RiskLevel.HIGH), SecurityMode.CLASSICAL, "ctx_1")
    assert r1.recommended_security_mode == r2.recommended_security_mode
    assert r1.requires_transition == r2.requires_transition

def test_repeated_decisions_do_not_vary(): # 27
    engine = DecisionEngine()
    for _ in range(10):
        r = engine.evaluate_decision(create_assessment(30.0, RiskLevel.MEDIUM), SecurityMode.CLASSICAL, "ctx_1")
        assert r.recommended_security_mode == SecurityMode.PQC
        
# 28 is satisfied by running full pytest suite
