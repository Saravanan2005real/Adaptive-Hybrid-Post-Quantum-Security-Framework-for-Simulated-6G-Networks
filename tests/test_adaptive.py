import pytest
from src.security.environment.manager import EnvironmentManager
from src.security.environment.models import (
    DeviceContext, CoreContext, EdgeContext, SecurityMode, AuthStatus, OperationalState, EnvironmentEventType
)
from src.security.risk.manager import RiskManager
from src.security.risk.models import RiskLevel
from src.events import EventLogger, EventType
from src.security.adaptive.models import AdaptiveDecisionResult
from src.security.adaptive.fusion import RiskFusion
from src.security.adaptive.policy import AdaptiveSecurityPolicy
from src.security.adaptive.transition import TransitionManager
from src.security.adaptive.engine import AdaptiveSecurityEngine

class MockMLPredictor:
    def __init__(self, fixed_score=50.0, fixed_level=RiskLevel.MEDIUM, should_fail=False):
        self.fixed_score = fixed_score
        self.fixed_level = fixed_level
        self.should_fail = should_fail
        
    def predict_context_risk(self, env, context_id):
        if self.should_fail:
            raise ValueError("ML model unavailable")
        return self.fixed_score, self.fixed_level

def setup_env(sec_mode=SecurityMode.CLASSICAL) -> EnvironmentManager:
    env = EnvironmentManager()
    env.register_core(CoreContext("core_0", OperationalState.ONLINE, [SecurityMode.CLASSICAL, SecurityMode.PQC, SecurityMode.HYBRID]))
    env.register_edge(EdgeContext("edge_0", OperationalState.ONLINE, [SecurityMode.CLASSICAL, SecurityMode.PQC, SecurityMode.HYBRID], "core_0"))
    env.register_device(DeviceContext("dev_0", "ue", OperationalState.ONLINE, [SecurityMode.CLASSICAL, SecurityMode.PQC, SecurityMode.HYBRID], ["ed25519"], ["mldsa"], "edge_0"))
    env.create_communication_context("ctx_0", "dev_0", "core_0", sec_mode)
    
    # Establish baseline healthy state so rule risk is 0 if no other factors
    env.update_security_context("ctx_0", auth_status=AuthStatus.AUTHENTICATING)
    env.update_security_context("ctx_0", auth_status=AuthStatus.AUTHENTICATED, session_id="sess_0", encryption_active=True)
    
    return env

def create_engine(env, ml_score=0.0, rule_weight=0.5, ml_weight=0.5, cooldown=3, downgrade=3):
    logger = EventLogger()
    risk = RiskManager(env, logger)
    from src.security.risk.scorer import determine_risk_level
    ml_mock = MockMLPredictor(fixed_score=ml_score, fixed_level=determine_risk_level(ml_score))
    engine = AdaptiveSecurityEngine(
        env_manager=env,
        risk_manager=risk,
        ml_predictor=ml_mock,
        logger=logger,
        rule_weight=rule_weight,
        ml_weight=ml_weight,
        cooldown_ticks=cooldown,
        downgrade_cycles=downgrade
    )
    return engine, logger

# Scenario 1: Escalation
def test_scenario_1_escalation():
    # Current CLASSICAL, Rule 60, ML 62 -> Fused 61 -> HIGH -> HYBRID -> APPLIED
    env = setup_env(SecurityMode.CLASSICAL)
    
    # Mock RiskManager's evaluate_context to return exactly 60
    engine, logger = create_engine(env, ml_score=62.0)
    
    # Patch risk evaluation manually for the test
    original_eval = engine.risk.evaluate_context
    def mock_eval(context_id):
        assessment = original_eval(context_id)
        assessment.risk_score = 60.0
        assessment.risk_level = RiskLevel.HIGH
        return assessment
    engine.risk.evaluate_context = mock_eval
    
    res = engine.evaluate("ctx_0")
    assert res.rule_risk_score == 60.0
    assert res.ml_risk_score == 62.0
    assert res.fused_risk_score == 61.0
    assert res.recommended_security_mode == SecurityMode.HYBRID
    assert res.transition_applied is True
    assert env.comm_contexts["ctx_0"].security.security_mode == SecurityMode.HYBRID

# Scenario 2: Downgrade Hysteresis
def test_scenario_2_downgrade_hysteresis():
    env = setup_env(SecurityMode.HYBRID)
    # Healthy env, rule=10 (because hybrid gives 10 overhead usually, wait, hybrid mode adds 10 risk? No, hybrid mode actually has 0 risk, but let's say rule is 0)
    # The requirement says rule=10. Let's just mock risk manager or accept rule=0 and ml=22 -> fused=11.
    engine, logger = create_engine(env, ml_score=22.0)
    
    # Evaluate 1: Fused = 11 (LOW) -> CLASSICAL. But wait 3 cycles.
    env.current_tick += 1
    res1 = engine.evaluate("ctx_0")
    assert res1.recommended_security_mode == SecurityMode.CLASSICAL
    assert res1.transition_applied is False
    assert env.comm_contexts["ctx_0"].security.security_mode == SecurityMode.HYBRID
    
    env.current_tick += 1
    res2 = engine.evaluate("ctx_0")
    assert res2.transition_applied is False
    
    env.current_tick += 1
    res3 = engine.evaluate("ctx_0")
    assert res3.transition_applied is True
    assert env.comm_contexts["ctx_0"].security.security_mode == SecurityMode.CLASSICAL

# Scenario 3: Cooldown Suppression
def test_scenario_3_cooldown():
    env = setup_env(SecurityMode.CLASSICAL)
    # Force an initial transition to start cooldown
    engine, logger = create_engine(env, ml_score=80.0, cooldown=3)
    original_eval = engine.risk.evaluate_context
    def mock_eval_1(context_id):
        assessment = original_eval(context_id)
        assessment.risk_score = 100.0
        assessment.risk_level = RiskLevel.CRITICAL
        return assessment
    engine.risk.evaluate_context = mock_eval_1
    
    env.current_tick = 10
    engine.evaluate("ctx_0") # Goes to HYBRID
    
    # Now set ML score to 42, Rule to 40 -> fused = 41 (MEDIUM) -> PQC.
    engine.ml.fixed_score = 42.0
    engine.ml.fixed_level = RiskLevel.MEDIUM
    
    def mock_eval_2(context_id):
        assessment = original_eval(context_id)
        assessment.risk_score = 40.0
        assessment.risk_level = RiskLevel.MEDIUM
        return assessment
    engine.risk.evaluate_context = mock_eval_2
    
    env.current_tick = 11 # Only 1 tick passed, cooldown is 3
    res = engine.evaluate("ctx_0")
    # Even if it's an escalation/downgrade, cooldown should block
    assert res.transition_applied is False
    assert res.suppression_reason == "Cooldown active"

# G. Weight validation
def test_weight_validation():
    with pytest.raises(ValueError):
        RiskFusion(-0.1, 1.1)
    with pytest.raises(ValueError):
        RiskFusion(0.5, 0.6)
        
# H. Score clamping
def test_score_clamping():
    fusion = RiskFusion(0.5, 0.5)
    score, level, dis = fusion.fuse(200.0, 300.0)
    assert score == 100.0
    
# T & U. Transition failure and atomicity
def test_transition_failure_atomicity():
    env = setup_env(SecurityMode.CLASSICAL)
    env.cores["core_0"].supported_security_modes = [SecurityMode.CLASSICAL, SecurityMode.PQC]
    
    engine, logger = create_engine(env, ml_score=100.0) # Wants HYBRID
    env.current_tick = 1
    
    # Capture complete state BEFORE transition
    ctx_before = env.comm_contexts["ctx_0"]
    sec_before = ctx_before.security
    auth_status_before = sec_before.auth_status
    encryption_before = sec_before.encryption_active
    session_before = sec_before.session_id
    
    res = engine.evaluate("ctx_0")
    
    assert res.transition_applied is False
    assert "Transition failed" in res.suppression_reason
    
    # Assert nothing mutated!
    sec_after = env.comm_contexts["ctx_0"].security
    assert sec_after.security_mode == SecurityMode.CLASSICAL
    assert sec_after.auth_status == auth_status_before
    assert sec_after.encryption_active == encryption_before
    assert sec_after.session_id == session_before
    
    # Assert FAILED event exists and COMPLETED doesn't
    events = [e.event_type for e in logger.events]
    assert EventType.SECURITY_TRANSITION_FAILED in events
    assert EventType.SECURITY_TRANSITION_COMPLETED not in events

def test_scoped_cooldown_and_hysteresis():
    env = setup_env(SecurityMode.CLASSICAL)
    # create second context
    env.create_communication_context("ctx_1", "dev_0", "core_0", SecurityMode.CLASSICAL)
    env.update_security_context("ctx_1", auth_status=AuthStatus.AUTHENTICATING)
    env.update_security_context("ctx_1", auth_status=AuthStatus.AUTHENTICATED, session_id="sess_2", encryption_active=True)
    
    engine, logger = create_engine(env, cooldown=3, downgrade=3)
    
    original_eval = engine.risk.evaluate_context
    def mock_eval(context_id):
        assessment = original_eval(context_id)
        assessment.risk_score = 100.0 if context_id == "ctx_0" else 0.0
        assessment.risk_level = RiskLevel.CRITICAL if context_id == "ctx_0" else RiskLevel.LOW
        return assessment
    engine.risk.evaluate_context = mock_eval
    engine.ml.fixed_score = 100.0
    engine.ml.fixed_level = RiskLevel.CRITICAL
    
    env.current_tick = 1
    # ctx_0 triggers escalation -> HYBRID
    res_0 = engine.evaluate("ctx_0")
    assert res_0.transition_applied is True
    
    engine.ml.fixed_score = 0.0
    engine.ml.fixed_level = RiskLevel.LOW
    
    # ctx_1 should not be blocked by ctx_0's cooldown
    env.current_tick = 2
    res_1 = engine.evaluate("ctx_1")
    # Rule=0, ML=0 -> LOW -> CLASSICAL (already in classical, mode already active)
    assert "Cooldown" not in res_1.suppression_reason

# S. ML prediction failure
def test_ml_prediction_failure():
    env = setup_env()
    engine, logger = create_engine(env)
    engine.ml.should_fail = True
    
    with pytest.raises(ValueError, match="ML prediction failed"):
        engine.evaluate("ctx_0")

# Y. No secrets in events
def test_no_secrets_in_events():
    env = setup_env()
    engine, logger = create_engine(env, ml_score=100.0)
    engine.evaluate("ctx_0")
    
    for event in logger.events:
        s = str(event.details).lower()
        assert "secret" not in s
        assert "key" not in s

# W. History integrity
def test_history_integrity():
    env = setup_env()
    engine, logger = create_engine(env)
    res = engine.evaluate("ctx_0")
    assert len(engine.history) == 1
    assert engine.history[0] == res

# AA. Deterministic repeated execution
def test_deterministic_execution():
    env1 = setup_env()
    eng1, _ = create_engine(env1, ml_score=60.0)
    res1 = eng1.evaluate("ctx_0")
    
    env2 = setup_env()
    eng2, _ = create_engine(env2, ml_score=60.0)
    res2 = eng2.evaluate("ctx_0")
    
    assert res1 == res2

# Event Ordering
def test_event_ordering():
    env = setup_env(SecurityMode.CLASSICAL)
    engine, logger = create_engine(env, ml_score=100.0) # Escalates to HYBRID immediately
    env.current_tick = 1
    
    # 1. Successful Transition
    res_success = engine.evaluate("ctx_0")
    assert res_success.transition_applied is True
    
    events = [e.event_type for e in logger.events if e.event_type.value.startswith("ADAPTIVE") or e.event_type.value.startswith("SECURITY_TRANSITION")]
    assert events == [
        EventType.ADAPTIVE_RISK_EVALUATED,
        EventType.ADAPTIVE_DECISION_CREATED,
        EventType.SECURITY_TRANSITION_STARTED,
        EventType.SECURITY_TRANSITION_COMPLETED
    ]
    logger.events.clear()
    
    # 2. Suppressed Transition (cooldown active)
    env.current_tick = 2
    # Mock ML to want CLASSICAL (downgrade)
    engine.ml.fixed_score = 0.0
    engine.ml.fixed_level = RiskLevel.LOW
    
    # We are in HYBRID. Rule is 0, ML is 0 -> LOW -> target is CLASSICAL.
    # But cooldown from tick 1 prevents downgrade counter from even starting, OR it starts downgrade counter but suppresses transition.
    res_suppress = engine.evaluate("ctx_0")
    assert res_suppress.transition_applied is False
    
    events = [e.event_type for e in logger.events if e.event_type.value.startswith("ADAPTIVE") or e.event_type.value.startswith("SECURITY_TRANSITION")]
    assert events == [
        EventType.ADAPTIVE_RISK_EVALUATED,
        EventType.ADAPTIVE_DECISION_CREATED,
        EventType.SECURITY_TRANSITION_SUPPRESSED
    ]
    logger.events.clear()
    
    # 3. Failed Transition
    env.current_tick = 3
    engine.ml.fixed_score = 0.0 # Wants CLASSICAL (downgrade)
    engine.ml.fixed_level = RiskLevel.LOW
    
    # Force bypass of hysteresis by mocking
    original_evaluate_transition = engine.transition.evaluate_transition
    def mock_eval_trans(cid, tick, cur, target):
        return True, ""
    engine.transition.evaluate_transition = mock_eval_trans
    
    # Corrupt environment context to fail update_security_context
    env.cores["core_0"].supported_security_modes = [] # Invalid for CLASSICAL
    
    res_fail = engine.evaluate("ctx_0")
    assert res_fail.transition_applied is False
    
    events = [e.event_type for e in logger.events if e.event_type.value.startswith("ADAPTIVE") or e.event_type.value.startswith("SECURITY_TRANSITION")]
    assert events == [
        EventType.ADAPTIVE_RISK_EVALUATED,
        EventType.ADAPTIVE_DECISION_CREATED,
        EventType.SECURITY_TRANSITION_STARTED,
        EventType.SECURITY_TRANSITION_FAILED
    ]
