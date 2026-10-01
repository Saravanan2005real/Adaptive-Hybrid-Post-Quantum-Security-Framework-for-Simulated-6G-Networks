import os
import sys
import json
import time
from typing import List, Dict, Any
from src.security.attacker.models import AttackType, AttackIntensity

# Import the existing Step 13 runner directly to guarantee source of truth
from experiments.step13_attack_defense import run_experiment_scenario

def generate_matrix() -> List[Dict[str, Any]]:
    matrix = []
    
    seeds = [42, 43, 44]
    intensities = [AttackIntensity.LOW, AttackIntensity.MEDIUM, AttackIntensity.HIGH]
    attack_types = [
        AttackType.AUTHENTICATION_ATTACK,
        AttackType.REPLAY_ATTACK,
        AttackType.MESSAGE_TAMPERING_ATTACK,
        AttackType.SESSION_ABUSE_ATTACK,
        AttackType.RESOURCE_PRESSURE_ATTACK
    ]
    
    for seed in seeds:
        # Control run for this seed
        matrix.append({
            "experiment_id": f"NO_ATTACK_SEED{seed}",
            "attack_type": "NO_ATTACK",
            "intensity": None,
            "seed": seed
        })
        
        for atk in attack_types:
            for intensity in intensities:
                matrix.append({
                    "experiment_id": f"ATTACK_{atk.name}_{intensity.name}_SEED{seed}",
                    "attack_type": atk,
                    "intensity": intensity,
                    "seed": seed
                })
                
    return matrix

def run_automated_experiments():
    print("STEP 14 — AUTOMATED EXPERIMENTS\n")
    start_time = time.perf_counter()
    
    matrix = generate_matrix()
    
    # Pre-flight Validation
    ids = [m["experiment_id"] for m in matrix]
    if len(ids) != len(set(ids)):
        print("Error: Duplicate experiment IDs detected in matrix.")
        return 1
        
    expected_size = len([42, 43, 44]) * (1 + 5 * 3) # 3 controls + 3*(5*3) = 48
    if len(matrix) != expected_size:
        print(f"Error: Matrix size {len(matrix)} != {expected_size}")
        return 1
        
    print(f"Generated experiment matrix with {len(matrix)} configurations.")
    print("Starting deterministic execution...\n")
    
    results_dir = os.path.join("results", "step14")
    runs_dir = os.path.join(results_dir, "runs")
    os.makedirs(runs_dir, exist_ok=True)
    
    aggregate = {
        "summary": {
            "total_runs": len(matrix),
            "completed_runs": 0,
            "failed_runs": 0,
            "total_execution_time": 0.0
        },
        "by_configuration": {}
    }
    
    all_runs = []
    
    for conf in matrix:
        eid = conf["experiment_id"]
        # run_experiment_scenario completely instantiates fresh state per call, satisfying isolation.
        
        # We need to adapt the s_def slightly
        s_def = {
            "id": eid,
            "attack_type": conf["attack_type"],
            "intensity": conf["intensity"]
        }
        
        try:
            res = run_experiment_scenario(s_def, seed=conf["seed"])
            
            # Format to Step 14 schema
            final_res = {
                "experiment_id": eid,
                "attack_type": res["attack_type"],
                "intensity": res["intensity"],
                "seed": conf["seed"],
                "simulation_duration": 6, # 5 to 10 tick window
                "status": "COMPLETED",
                "ground_truth": res["ground_truth"],
                "security_observations": res["response"],
                "risk": {
                    "rule_pre": res["pre_state"]["rule_risk_score"],
                    "rule_post": res["post_state"]["rule_risk_score"],
                    "rule_delta": res["metrics"]["risk_delta"],
                    "ml_pre": res["pre_state"]["ml_risk_score"],
                    "ml_post": res["post_state"]["ml_risk_score"],
                    "ml_delta": res["metrics"]["ml_risk_delta"]
                },
                "adaptive_response": {
                    "mode_pre": res["pre_state"]["security_mode"],
                    "mode_post": res["post_state"]["security_mode"],
                    "transition_count": res["response"]["mode_changed"],
                    "transition_latency_ticks": res["response"]["transition_latency_ticks"]
                },
                "performance": {
                    "execution_time_seconds": res["metrics"]["execution_time_sec"]
                }
            }
            aggregate["summary"]["completed_runs"] += 1
            
        except Exception as e:
            print(f"Run {eid} failed: {e}")
            final_res = {
                "experiment_id": eid,
                "attack_type": conf["attack_type"].value if conf["attack_type"] != "NO_ATTACK" else "NO_ATTACK",
                "intensity": conf["intensity"].value if conf["intensity"] else "N/A",
                "seed": conf["seed"],
                "status": "FAILED",
                "error": str(e)
            }
            aggregate["summary"]["failed_runs"] += 1
            
        # Write individual file
        with open(os.path.join(runs_dir, f"{eid}.json"), "w") as f:
            json.dump(final_res, f, indent=2)
            
        all_runs.append(final_res)
        
    end_time = time.perf_counter()
    aggregate["summary"]["total_execution_time"] = end_time - start_time
    
    # Aggregation
    # Group by attack_type + intensity
    groups = {}
    for r in all_runs:
        atk = r["attack_type"]
        int_v = r["intensity"]
        key = f"{atk}_{int_v}"
        
        if key not in groups:
            groups[key] = {
                "attack_type": atk,
                "intensity": int_v,
                "number_of_runs": 0,
                "completed_runs": 0,
                "failed_runs": 0,
                "total_attack_injections": 0,
                "rule_risk_deltas": [],
                "ml_risk_deltas": [],
                "transition_count": 0,
                "transition_latencies": [],
                "execution_times": []
            }
            
        groups[key]["number_of_runs"] += 1
        if r["status"] == "COMPLETED":
            groups[key]["completed_runs"] += 1
            # Injections: calculated dynamically
            injs = r["ground_truth"].get("events_generated", 0) if r["ground_truth"] else 0
            groups[key]["total_attack_injections"] += injs
            groups[key]["rule_risk_deltas"].append(r["risk"]["rule_delta"])
            groups[key]["ml_risk_deltas"].append(r["risk"]["ml_delta"])
            groups[key]["transition_count"] += r["adaptive_response"]["transition_count"]
            if r["adaptive_response"]["transition_count"] > 0:
                groups[key]["transition_latencies"].append(r["adaptive_response"]["transition_latency_ticks"])
            groups[key]["execution_times"].append(r["performance"]["execution_time_seconds"])
        else:
            groups[key]["failed_runs"] += 1
            
    # Calculate means
    for k, v in groups.items():
        if v["completed_runs"] > 0:
            c = v["completed_runs"]
            v["mean_attack_injections"] = v["total_attack_injections"] / c
            v["mean_rule_risk_delta"] = sum(v["rule_risk_deltas"]) / c
            v["mean_ml_risk_delta"] = sum(v["ml_risk_deltas"]) / c
            v["mean_transition_count"] = v["transition_count"] / c
            if v["transition_latencies"]:
                v["mean_transition_latency"] = sum(v["transition_latencies"]) / len(v["transition_latencies"])
            else:
                v["mean_transition_latency"] = "N/A"
            v["mean_execution_time"] = sum(v["execution_times"]) / c
            v["min_execution_time"] = min(v["execution_times"])
            v["max_execution_time"] = max(v["execution_times"])
        
        # Clean up raw lists before saving
        del v["rule_risk_deltas"]
        del v["ml_risk_deltas"]
        del v["transition_latencies"]
        del v["execution_times"]
        
        aggregate["by_configuration"][k] = v
        
    with open(os.path.join(results_dir, "aggregate_results.json"), "w") as f:
        json.dump(aggregate, f, indent=2)
        
    # Execution Summary
    with open(os.path.join(results_dir, "experiment_matrix.json"), "w") as f:
        # Just save the matrix def
        def_matrix = []
        for m in matrix:
            def_matrix.append({
                "experiment_id": m["experiment_id"],
                "attack_type": m["attack_type"].value if m["attack_type"] != "NO_ATTACK" else "NO_ATTACK",
                "intensity": m["intensity"].value if m["intensity"] else "N/A",
                "seed": m["seed"]
            })
        json.dump(def_matrix, f, indent=2)
        
    print(f"Completed {aggregate['summary']['completed_runs']}/{aggregate['summary']['total_runs']} experiments.")
    if aggregate['summary']['failed_runs'] > 0:
        print(f"FAILED: {aggregate['summary']['failed_runs']}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(run_automated_experiments())
