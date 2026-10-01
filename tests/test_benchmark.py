import os
import json
import pytest
import time
from experiments.step15_benchmarking import generate_matrix

def test_matrix_generation_completeness():
    matrix = generate_matrix()
    
    assert len(matrix) == 20
    
    ids = [m["experiment_id"] for m in matrix]
    assert len(set(ids)) == 20, "Duplicate IDs in matrix"
    
    modes = {m["security_mode"] for m in matrix}
    assert modes == {"CLASSICAL", "PQC", "HYBRID", "ADAPTIVE_HYBRID"}
    
    seeds = {m["seed"] for m in matrix}
    assert seeds == {42, 43, 44, 45, 46}
    
    for mode in modes:
        mode_runs = [m for m in matrix if m["security_mode"] == mode]
        assert len(mode_runs) == 5
        
    for seed in seeds:
        seed_runs = [m for m in matrix if m["seed"] == seed]
        assert len(seed_runs) == 4

def test_benchmark_schema_and_na_handling():
    agg_path = os.path.join("results", "step15", "aggregate_results.json")
    if not os.path.exists(agg_path):
        pytest.skip("Step 15 results not found")
        
    with open(agg_path, "r") as f:
        agg = json.load(f)["aggregates_by_mode"]
        
    for mode, data in agg.items():
        assert data["count"] == 5
        assert "network_metrics.throughput" in data
        
    with open(os.path.join("results", "step15", "benchmark_results.json"), "r") as f:
        results = json.load(f)
        
    for res in results:
        assert "status" in res
        assert "network_metrics" in res
        assert "adaptive_metrics" in res
        
        # N/A handling check
        if res["security_mode"] != "ADAPTIVE_HYBRID":
            assert res["adaptive_metrics"]["initial_security_mode"] == "N/A"
            assert res["adaptive_metrics"]["adaptive_orchestration_execution_time"] == "N/A"
        else:
            assert res["adaptive_metrics"]["initial_security_mode"] != "N/A"

def test_secret_exclusion():
    if not os.path.exists(os.path.join("results", "step15", "benchmark_results.json")):
        pytest.skip("Step 15 results not found")
        
    with open(os.path.join("results", "step15", "benchmark_results.json"), "r") as f:
        content = f.read().lower()
        
    # Check that secrets don't appear in output
    assert "private_key" not in content
    assert "session_key" not in content

def test_reproducibility():
    from experiments.step15_benchmarking import run_benchmark
    # Execute a small benchmark to test reproducibility
    res1 = run_benchmark("TEST_R1", "HYBRID", 42)
    res2 = run_benchmark("TEST_R2", "HYBRID", 42)
    
    # We ignore execution times and UUIDs (which might be in experiment_id)
    del res1["experiment_id"]
    del res2["experiment_id"]
    del res1["metrics"]["execution_time_sec"]
    del res2["metrics"]["execution_time_sec"]
    del res1["security_overhead_metrics"]["security_processing_time"]
    del res2["security_overhead_metrics"]["security_processing_time"]
    del res1["security_overhead_metrics"]["network_processing_time"]
    del res2["security_overhead_metrics"]["network_processing_time"]
    del res1["security_overhead_metrics"]["combined_execution_time"]
    del res2["security_overhead_metrics"]["combined_execution_time"]
    del res1["security_overhead_metrics"]["security_overhead"]
    del res2["security_overhead_metrics"]["security_overhead"]
    del res1["authentication_metrics"]["authentication_latency"]
    del res2["authentication_metrics"]["authentication_latency"]
    del res1["key_establishment_metrics"]["key_establishment_latency"]
    del res2["key_establishment_metrics"]["key_establishment_latency"]
    del res1["encryption_metrics"]["encryption_latency"]
    del res2["encryption_metrics"]["encryption_latency"]
    del res1["decryption_metrics"]["decryption_latency"]
    del res2["decryption_metrics"]["decryption_latency"]
    
    if "adaptive_orchestration_execution_time" in res1["adaptive_metrics"] and res1["adaptive_metrics"]["adaptive_orchestration_execution_time"] != "N/A":
        del res1["adaptive_metrics"]["adaptive_orchestration_execution_time"]
        del res2["adaptive_metrics"]["adaptive_orchestration_execution_time"]
    
    assert res1 == res2

def test_state_isolation():
    from experiments.step15_benchmarking import run_benchmark
    res1 = run_benchmark("ISO_1", "ADAPTIVE_HYBRID", 42)
    res2 = run_benchmark("ISO_2", "ADAPTIVE_HYBRID", 42)
    
    # If isolation failed, res2's adaptive risk metrics would accumulate from res1.
    assert res1["adaptive_metrics"]["rule_risk"] == res2["adaptive_metrics"]["rule_risk"]

