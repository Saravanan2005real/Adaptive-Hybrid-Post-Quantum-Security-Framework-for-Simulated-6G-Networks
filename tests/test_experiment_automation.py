import os
import json
import pytest
from src.security.attacker.models import AttackType, AttackIntensity
from experiments.step14_automated_runner import generate_matrix

def test_matrix_generation_completeness():
    matrix = generate_matrix()
    
    # 3 seeds * (1 control + 5 attack types * 3 intensities) = 3 * 16 = 48
    assert len(matrix) == 48
    
    # Check deterministic IDs
    ids = [m["experiment_id"] for m in matrix]
    assert len(set(ids)) == 48, "Duplicate IDs in matrix"
    
    # Check all seeds are present
    seeds = {m["seed"] for m in matrix}
    assert seeds == {42, 43, 44}
    
    # Check control conditions
    controls = [m for m in matrix if m["attack_type"] == "NO_ATTACK"]
    assert len(controls) == 3
    assert controls[0]["experiment_id"] == "NO_ATTACK_SEED42"

def test_automated_results_schema():
    # Only run if step 14 has actually executed locally
    agg_path = os.path.join("results", "step14", "aggregate_results.json")
    if not os.path.exists(agg_path):
        pytest.skip("Step 14 results not found")
        
    with open(agg_path, "r") as f:
        agg = json.load(f)
        
    assert "summary" in agg
    assert "by_configuration" in agg
    
    assert agg["summary"]["total_runs"] == 48
    assert agg["summary"]["completed_runs"] == 48
    assert agg["summary"]["failed_runs"] == 0

def test_clean_state_isolation():
    # We can test this by running two consecutive high-intensity attacks from step13 directly
    # and ensuring the second one doesn't inherit risk from the first.
    from experiments.step13_attack_defense import run_experiment_scenario
    
    s_def = {"id": "scen1", "attack_type": AttackType.AUTHENTICATION_ATTACK, "intensity": AttackIntensity.HIGH}
    res1 = run_experiment_scenario(s_def, seed=42)
    
    s_def2 = {"id": "scen2", "attack_type": AttackType.AUTHENTICATION_ATTACK, "intensity": AttackIntensity.HIGH}
    res2 = run_experiment_scenario(s_def2, seed=42)
    
    # If isolation failed, res2's pre_state risk would be elevated (from res1)
    # We assert they start at the exact same baseline (which happens to be 10.0 due to device context defaults)
    assert res1["pre_state"]["rule_risk_score"] == res2["pre_state"]["rule_risk_score"]
    
    # The deltas should be identical because state was fresh
    assert res1["metrics"]["risk_delta"] == res2["metrics"]["risk_delta"]

def test_reproducibility_automated():
    from experiments.step13_attack_defense import run_experiment_scenario
    s_def = {"id": "TEST", "attack_type": AttackType.SESSION_ABUSE_ATTACK, "intensity": AttackIntensity.MEDIUM}
    
    # Using seed 42
    res_a = run_experiment_scenario(s_def, seed=42)
    res_b = run_experiment_scenario(s_def, seed=42)
    
    # Using seed 43
    res_c = run_experiment_scenario(s_def, seed=43)
    
    # Check A == B (ignoring execution time)
    del res_a["metrics"]["execution_time_sec"]
    del res_b["metrics"]["execution_time_sec"]
    assert res_a == res_b
    
    # For A and C, there might be slight differences in random nonces but for session abuse
    # the failures are deterministic. However, the ground truth and risk should match exactly.
    assert res_a["metrics"]["attack_injections"] == res_c["metrics"]["attack_injections"]
    assert res_a["metrics"]["risk_delta"] == res_c["metrics"]["risk_delta"]
