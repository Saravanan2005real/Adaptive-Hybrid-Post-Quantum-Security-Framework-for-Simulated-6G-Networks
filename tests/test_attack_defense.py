import pytest
from src.security.attacker.models import AttackType, AttackIntensity
from experiments.step13_attack_defense import run_experiment_scenario

def test_no_attack_control_condition():
    s_def = {"id": "CONTROL", "attack_type": "NO_ATTACK", "intensity": None}
    res = run_experiment_scenario(s_def, seed=42)
    
    assert res["attack_type"] == "NO_ATTACK"
    assert res["metrics"]["attack_attempts"] == 0
    assert res["metrics"]["attack_injections"] == 0
    assert res["response"]["mode_changed"] == 0
    assert res["response"]["transition_latency_ticks"] == "N/A"
    assert res["response"]["authentication_failures"] == 0

def test_authentication_attack_high_triggers_transition():
    s_def = {"id": "SCEN_B", "attack_type": AttackType.AUTHENTICATION_ATTACK, "intensity": AttackIntensity.HIGH}
    res = run_experiment_scenario(s_def, seed=42)
    
    # Verify exact accounting from ground truth
    assert res["metrics"]["attack_attempts"] == 120
    assert res["metrics"]["attack_injections"] == 120
    
    # 120 attempts = 120 auth failures
    assert res["response"]["authentication_failures"] == 120
    
    # Risk should escalate
    assert res["metrics"]["risk_delta"] > 0
    
    # Mode should have changed (transitioned)
    assert res["response"]["mode_changed"] == 1
    assert isinstance(res["response"]["transition_latency_ticks"], int)
    assert res["response"]["transition_latency_ticks"] >= 0
    assert res["response"]["transition_target_mode"] in ["PQC", "HYBRID"]

def test_replay_attack_low():
    s_def = {"id": "SCEN_C", "attack_type": AttackType.REPLAY_ATTACK, "intensity": AttackIntensity.LOW}
    res = run_experiment_scenario(s_def, seed=42)
    
    assert res["metrics"]["attack_attempts"] == 6
    assert res["metrics"]["attack_injections"] == 6
    assert res["response"]["replay_failures"] > 0
    
    # Mode shouldn't necessarily change for just 6 failures if unmapped to risk,
    # but the measurements must be accurate.
    assert res["response"]["authentication_failures"] == 0

def test_no_fabricated_metrics_invariant():
    s_def = {"id": "SCEN_H", "attack_type": AttackType.SESSION_ABUSE_ATTACK, "intensity": AttackIntensity.HIGH}
    res = run_experiment_scenario(s_def, seed=42)
    
    # SESSION ABUSE generates AUTHENTICATION_FAILED but not REPLAY/INTEGRITY
    assert res["metrics"]["attack_attempts"] == 120
    assert res["response"]["replay_failures"] == 0
    assert res["response"]["integrity_failures"] == 0
    
def test_pre_post_states_captured():
    s_def = {"id": "CONTROL", "attack_type": "NO_ATTACK", "intensity": None}
    res = run_experiment_scenario(s_def, seed=42)
    
    assert "security_mode" in res["pre_state"]
    assert "rule_risk_score" in res["pre_state"]
    assert "ml_risk_score" in res["pre_state"]
    
    assert "security_mode" in res["post_state"]
    assert "rule_risk_score" in res["post_state"]
    assert "ml_risk_score" in res["post_state"]
    
def test_reproducibility():
    s_def = {"id": "SCEN_G", "attack_type": AttackType.SESSION_ABUSE_ATTACK, "intensity": AttackIntensity.LOW}
    res1 = run_experiment_scenario(s_def, seed=123)
    res2 = run_experiment_scenario(s_def, seed=123)
    
    # Remove execution time before asserting equality
    del res1["metrics"]["execution_time_sec"]
    del res2["metrics"]["execution_time_sec"]
    
    assert res1 == res2
