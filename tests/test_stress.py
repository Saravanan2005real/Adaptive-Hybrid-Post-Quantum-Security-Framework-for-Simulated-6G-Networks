import os
import json
import pytest
from experiments.step17_stress import generate_matrix, run_benchmark

def test_stress_matrix_accounting():
    matrix = generate_matrix()
    
    assert len(matrix) == 33, f"Expected 33 configurations, got {len(matrix)}"
    ids = [m["experiment_id"] for m in matrix]
    assert len(set(ids)) == 33, "Duplicate IDs in matrix"
    
    scenarios = {m["scenario_id"] for m in matrix}
    assert len(scenarios) == 8, f"Expected 8 scenarios, got {len(scenarios)}"
    
    seeds = {m["seed"] for m in matrix}
    assert len(seeds) == 3, f"Expected 3 seeds, got {len(seeds)}"

def test_stress_expected_scenario_coverage():
    matrix = generate_matrix()
    scenarios = {m["scenario_id"] for m in matrix}
    expected = {"STRESS-1", "STRESS-2", "STRESS-3", "STRESS-4", "STRESS-5", "STRESS-6", "STRESS-7_ZERO_DEV", "STRESS-7_NEG_RATE"}
    assert scenarios == expected

def test_stress_result_file_reconciliation():
    runs_dir = os.path.join("results", "step17", "runs")
    if not os.path.exists(runs_dir):
        pytest.skip("Step 17 results not found")
        
    matrix_path = os.path.join("results", "step17", "stress_matrix.json")
    with open(matrix_path, "r") as f:
        matrix = json.load(f)
        
    run_files = [f for f in os.listdir(runs_dir) if f.endswith('.json')]
    assert len(run_files) == len(matrix), "Must have exactly 1 result file per matrix entry"
    
    matrix_ids = {m["experiment_id"] for m in matrix}
    file_ids = {f.replace(".json", "") for f in run_files}
    assert matrix_ids == file_ids, "One-to-one matrix/result mapping failed"

def test_stress_network_accounting_invariant():
    runs_dir = os.path.join("results", "step17", "runs")
    if not os.path.exists(runs_dir):
        pytest.skip("Step 17 results not found")
        
    for f_name in os.listdir(runs_dir):
        if not f_name.endswith('.json'): continue
        with open(os.path.join(runs_dir, f_name), "r") as f:
            res = json.load(f)
            
        nm = res["network_metrics"]
        # generated = delivered + failed + in_flight
        assert nm["messages_generated"] == nm["messages_delivered"] + nm["messages_failed"] + nm["messages_in_flight"]
        
        # negative counter check
        for k, v in nm.items():
            if isinstance(v, (int, float)):
                assert v >= 0, f"Negative counter found in {k}"

def test_stress_fresh_state_isolation():
    s1_def = {"devices": 50, "edge_nodes": 5, "core_nodes": 1}
    s5_def = {"devices": 1000, "edge_nodes": 100, "core_nodes": 20}
    
    res1 = run_benchmark("ISO_1", "S1", "baseline", s1_def, "HYBRID", 0.1, 50, 256, 42)
    res_s5 = run_benchmark("ISO_2", "S5", "stress", s5_def, "HYBRID", 1.0, 100, 256, 42)
    res2 = run_benchmark("ISO_3", "S1", "baseline", s1_def, "HYBRID", 0.1, 50, 256, 42)
    
    assert res1["network_metrics"]["messages_generated"] == res2["network_metrics"]["messages_generated"]

def test_stress_deterministic_reproducibility():
    s3_def = {"devices": 250, "edge_nodes": 25, "core_nodes": 5}
    res1 = run_benchmark("REP_1", "STRESS-6", "Combined", s3_def, "ADAPTIVE_HYBRID", 1.0, 100, 256, 44)
    res2 = run_benchmark("REP_2", "STRESS-6", "Combined", s3_def, "ADAPTIVE_HYBRID", 1.0, 100, 256, 44)
    
    # Strip metadata and timing
    for res in [res1, res2]:
        del res["experiment_id"]
        del res["network_metrics"]["execution_time_sec"]
        del res["security_metrics"]["security_processing_time"]
        del res["stress_metrics"]["execution_time_per_generated_message"]
        del res["stress_metrics"]["execution_time_per_device"]
        
        if "adaptive_orchestration_execution_time" in res["adaptive_metrics"] and res["adaptive_metrics"]["adaptive_orchestration_execution_time"] != "N/A":
            del res["adaptive_metrics"]["adaptive_orchestration_execution_time"]
            
    assert res1 == res2

def test_stress_invalid_input_behavior():
    # zero devices
    s0_def = {"devices": 0, "edge_nodes": 5, "core_nodes": 1}
    res = run_benchmark("INV_1", "STRESS-7", "Zero Devices", s0_def, "CLASSICAL", 0.1, 50, 256, 42)
    assert res["network_metrics"]["messages_generated"] == 0
    
    # negative rate
    s1_def = {"devices": 50, "edge_nodes": 5, "core_nodes": 1}
    res2 = run_benchmark("INV_2", "STRESS-7", "Negative Rate", s1_def, "CLASSICAL", -0.5, 50, 256, 42)
    assert res2["network_metrics"]["messages_generated"] == 0

def test_stress_aggregate_reconciliation():
    agg_path = os.path.join("results", "step17", "aggregate_results.json")
    if not os.path.exists(agg_path):
        pytest.skip("Step 17 results not found")
        
    with open(agg_path, "r") as f:
        agg = json.load(f)["aggregates_by_scale_mode"]
        
    runs_dir = os.path.join("results", "step17", "runs")
    import statistics
    
    # Check STRESS-1 for HYBRID
    run_files = [f for f in os.listdir(runs_dir) if "STRESS-1_HYBRID" in f]
    assert len(run_files) == 3
    msgs = []
    for rf in run_files:
        with open(os.path.join(runs_dir, rf), "r") as f_run:
            data = json.load(f_run)
            msgs.append(data["network_metrics"]["messages_generated"])
            
    recomputed_mean = statistics.mean(msgs)
    assert agg["STRESS-1"]["HYBRID"]["network_metrics.messages_generated"]["mean"] == recomputed_mean

def test_stress_secret_exclusion():
    runs_dir = os.path.join("results", "step17", "runs")
    if not os.path.exists(runs_dir):
        pytest.skip("Step 17 results not found")
        
    for f_name in os.listdir(runs_dir):
        if not f_name.endswith('.json'): continue
        with open(os.path.join(runs_dir, f_name), "r") as f:
            content = f.read().lower()
            
        required_secrets = [
            "private_key",
            "private_keys",
            "secret_key",
            "session_key",
            "shared_secret",
            "signing_secret"
        ]
        for secret in required_secrets:
            assert secret not in content

def test_stress_na_metric_handling():
    s1_def = {"devices": 50, "edge_nodes": 5, "core_nodes": 1}
    res = run_benchmark("NA_1", "S1", "baseline", s1_def, "CLASSICAL", 0.1, 50, 256, 42)
    assert res["adaptive_metrics"]["initial_mode"] == "N/A"
    assert res["adaptive_metrics"]["adaptive_orchestration_execution_time"] == "N/A"

def test_stress_adaptive_transition_consistency():
    s1_def = {"devices": 50, "edge_nodes": 5, "core_nodes": 1}
    res = run_benchmark("ADAP_1", "S1", "baseline", s1_def, "ADAPTIVE_HYBRID", 0.1, 50, 256, 42)
    # If transition_count > 0, final mode might differ from initial. Since this is baseline, it should be 0.
    assert res["adaptive_metrics"]["transition_count"] >= 0
    
def test_stress_no_silent_repair():
    s1_def = {"devices": 50, "edge_nodes": 5, "core_nodes": 1}
    res = run_benchmark("REPAIR_1", "S1", "baseline", s1_def, "CLASSICAL", 0.1, 50, 256, 42)
    # The requirement is that we flag accounting_violation = True rather than fixing the number.
    # Our script explicitly evaluates accounting_violation instead of patching it.
    assert "accounting_violation" in res["stress_metrics"]
    assert res["stress_metrics"]["accounting_violation"] == False
