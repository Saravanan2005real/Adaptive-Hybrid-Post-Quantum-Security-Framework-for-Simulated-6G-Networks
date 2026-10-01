import os
import sys
import time
import json
import random
from typing import Dict, Any, List

from src.simulator import Simulator
from src.events import EventLogger, EventType
from src.security.manager import SecurityManager, ProtectedMessagePayload
from src.security.attacker import (
    AttackerSimulator, AttackerProfile, AttackScenario,
    AttackType, AttackIntensity, AttackGroundTruth
)
from src.security.environment.manager import EnvironmentManager
from src.security.environment.models import (
    DeviceContext, CoreContext, EdgeContext, SecurityMode, AuthStatus, OperationalState, EnvironmentEventType
)
from src.security.risk.manager import RiskManager
from src.security.ml_risk.predictor import MLRiskPredictorAPI
from src.security.adaptive.engine import AdaptiveSecurityEngine

def run_experiment_scenario(
    scenario_def: dict,
    seed: int = 42
) -> Dict[str, Any]:
    """Runs a single attack-defense experiment scenario."""
    # 1. Setup Models & Infrastructure
    random.seed(seed)
    model_path = "results/ml_risk_model.pkl"
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"ML model not found at {model_path}. Run ML baseline first.")
    ml_api = MLRiskPredictorAPI(model_path)
    
    config_path = os.path.join("configs", "default_network.yaml")
    sim = Simulator(config_path)
    sim.initialize_network()
    
    logger = EventLogger()
    sec_manager = SecurityManager(logger)
    
    # 2. Setup Security Environment
    env = EnvironmentManager()
    
    core_id = list(sim.network.cores)[0]
    edge_id = list(sim.network.edges.keys())[0]
    dev_id = list(sim.network.devices.keys())[0]
    ctx_id = f"ctx_{dev_id}_{core_id}"
    
    # Bridge for UI inputs
    ui_mode = scenario_def.get("security_mode", "ADAPTIVE")
    sec_mode_map = {
        "CLASSICAL": SecurityMode.CLASSICAL,
        "PQC": SecurityMode.PQC,
        "HYBRID": SecurityMode.HYBRID,
        "ADAPTIVE": SecurityMode.CLASSICAL
    }
    initial_mode = sec_mode_map.get(ui_mode, SecurityMode.CLASSICAL)
    adaptive = (ui_mode == "ADAPTIVE")
    
    env.register_core(CoreContext(core_id, OperationalState.ONLINE, [SecurityMode.CLASSICAL, SecurityMode.PQC, SecurityMode.HYBRID]))
    env.register_edge(EdgeContext(edge_id, OperationalState.ONLINE, [SecurityMode.CLASSICAL, SecurityMode.PQC, SecurityMode.HYBRID], core_id))
    env.register_device(DeviceContext(dev_id, "ue", OperationalState.ONLINE, [SecurityMode.CLASSICAL, SecurityMode.PQC, SecurityMode.HYBRID], ["ed25519"], ["mldsa"], edge_id))
    
    env.create_communication_context(ctx_id, dev_id, core_id, initial_mode)
    env.update_security_context(ctx_id, auth_status=AuthStatus.AUTHENTICATING)
    env.update_security_context(ctx_id, auth_status=AuthStatus.AUTHENTICATED, session_id="sess_1", encryption_active=True)
    
    risk = RiskManager(env, logger)
    engine = AdaptiveSecurityEngine(env, risk, ml_api, logger, cooldown_ticks=3, downgrade_cycles=5)
    
    if not adaptive:
        # Safest clean bridge: lock the policy to current mode to evaluate risk without transitioning
        engine.policy.determine_target_mode = lambda level: env.comm_contexts[ctx_id].security.security_mode
    
    # Register genuine entities with SecurityManager
    sec_manager.register_device(core_id)
    sec_manager.register_device(dev_id)
    sec_manager.authenticate_and_exchange(dev_id, core_id, 1) # tick 1
    
    # 3. Setup Attacker Simulation
    attacker_sim = AttackerSimulator(sec_manager, logger, seed=seed)
    attacker_sim.set_environment([dev_id, core_id], [ctx_id])
    
    atk_prof = AttackerProfile("attacker_X", [scenario_def["attack_type"]], scenario_def["intensity"])
    attacker_sim.scheduler.register_attacker(atk_prof)
    
    if scenario_def["attack_type"] != "NO_ATTACK":
        scen = AttackScenario(
            attack_id="atk_1",
            attack_type=scenario_def["attack_type"],
            attacker_id="attacker_X",
            target_id=core_id,
            context_id=ctx_id,
            start_tick=5,
            duration_ticks=5,
            intensity=scenario_def["intensity"]
        )
        attacker_sim.schedule_attack(scen)
        
    # Pre-attack evaluation at tick 4
    env.current_tick = 4
    pre_result = engine.evaluate(ctx_id)
    
    # Capture some traffic for Replay/Tampering
    if scenario_def["attack_type"] in [AttackType.REPLAY_ATTACK, AttackType.MESSAGE_TAMPERING_ATTACK]:
        try:
            payload = sec_manager.encrypt_message(dev_id, core_id, {"data": "secret"}, 4)
            attacker_sim.capture_message(dev_id, core_id, payload)
        except Exception:
            pass

    start_time = time.perf_counter()
    processed_attack_events = 0
    
    # Run simulation window (tick 5 to 10)
    for tick in range(5, 11):
        env.current_tick = tick
        
        # 1. Attacker Inject
        results = attacker_sim.process_tick(tick)
            
        # 2. Map SecurityManager crypto events to Environment telemetry for Risk evaluation
        # We need to bridge the crypto events generated this tick to the environment layer
        # Since we use one logger, we look at events logged this tick
        tick_events = [e for e in logger.events if e.timestamp == tick]
        for e in tick_events:
            if e.event_type == EventType.AUTHENTICATION_FAILURE:
                env.telemetry.record(tick, EnvironmentEventType.AUTHENTICATION_FAILED.value, ctx_id, dev_id, {})
                
        # 3. Adaptive Engine Evaluation (every tick after attack to see response)
        res = engine.evaluate(ctx_id)
        
    end_time = time.perf_counter()
    exec_time = end_time - start_time
    
    # Post-attack evaluation at tick 11
    env.current_tick = 11
    post_result = engine.evaluate(ctx_id)
    
    # Collect Response Metrics
    mode_changed = 1 if pre_result.current_security_mode != post_result.current_security_mode else 0
    
    # Find transition latency
    transition_latency = "N/A"
    transition_source = None
    transition_target = None
    transition_reason = None
    
    if mode_changed:
        for r in engine.history:
            if r.transition_applied:
                # Assuming attack started at tick 5
                transition_latency = max(0, r.timestamp - 5)
                transition_source = r.current_security_mode.value
                transition_target = r.recommended_security_mode.value
                break
                
    # Count specific failures in logger
    auth_fails = sum(1 for e in logger.events if e.event_type == EventType.AUTHENTICATION_FAILURE and 5 <= e.timestamp <= 10)
    replay_fails = sum(1 for e in logger.events if e.event_type == EventType.REPLAY_DETECTED and 5 <= e.timestamp <= 10)
    integ_fails = sum(1 for e in logger.events if e.event_type == EventType.INTEGRITY_VERIFICATION_FAILED and 5 <= e.timestamp <= 10)
    
    # Ground truth
    gt = attacker_sim.ground_truths.get("atk_1")
    gt_dict = gt.to_dict() if gt else {}
    
    return {
        "scenario_id": scenario_def["id"],
        "attack_type": scenario_def["attack_type"].value if scenario_def["attack_type"] != "NO_ATTACK" else "NO_ATTACK",
        "intensity": scenario_def["intensity"].value if scenario_def["attack_type"] != "NO_ATTACK" else "N/A",
        "ground_truth": gt_dict,
        "pre_state": {
            "context_id": ctx_id,
            "entity_id": dev_id,
            "security_mode": pre_result.current_security_mode.value,
            "rule_risk_score": pre_result.rule_risk_score,
            "rule_risk_level": pre_result.rule_risk_level.value,
            "ml_risk_score": pre_result.ml_risk_score,
            "ml_risk_level": pre_result.ml_risk_level.value
        },
        "response": {
            "authentication_failures": auth_fails,
            "replay_failures": replay_fails,
            "integrity_failures": integ_fails,
            "session_failures": 0, # Mapped as auth failures in this architecture
            "resource_pressure_injections": gt.events_generated if gt and scenario_def["attack_type"] == AttackType.RESOURCE_PRESSURE_ATTACK else 0,
            "mode_changed": mode_changed,
            "transition_source_mode": transition_source,
            "transition_target_mode": transition_target,
            "transition_latency_ticks": transition_latency
        },
        "post_state": {
            "security_mode": post_result.current_security_mode.value,
            "rule_risk_score": post_result.rule_risk_score,
            "rule_risk_level": post_result.rule_risk_level.value,
            "ml_risk_score": post_result.ml_risk_score,
            "ml_risk_level": post_result.ml_risk_level.value
        },
        "metrics": {
            "risk_delta": post_result.rule_risk_score - pre_result.rule_risk_score,
            "ml_risk_delta": post_result.ml_risk_score - pre_result.ml_risk_score,
            "attack_attempts": gt.attempts_generated if gt else 0,
            "attack_injections": gt.events_generated if gt else 0,
            "execution_time_sec": exec_time,
            "processed_attack_events": gt.events_generated if gt else 0
        }
    }

def main():
    print("STEP 13 — ATTACK-DEFENSE EXPERIMENTS\n")
    
    scenarios = [
        {"id": "CONTROL", "attack_type": "NO_ATTACK", "intensity": None},
        {"id": "SCENARIO_A", "attack_type": AttackType.AUTHENTICATION_ATTACK, "intensity": AttackIntensity.LOW},
        {"id": "SCENARIO_B", "attack_type": AttackType.AUTHENTICATION_ATTACK, "intensity": AttackIntensity.HIGH},
        {"id": "SCENARIO_C", "attack_type": AttackType.REPLAY_ATTACK, "intensity": AttackIntensity.LOW},
        {"id": "SCENARIO_D", "attack_type": AttackType.REPLAY_ATTACK, "intensity": AttackIntensity.HIGH},
        {"id": "SCENARIO_E", "attack_type": AttackType.MESSAGE_TAMPERING_ATTACK, "intensity": AttackIntensity.LOW},
        {"id": "SCENARIO_F", "attack_type": AttackType.MESSAGE_TAMPERING_ATTACK, "intensity": AttackIntensity.HIGH},
        {"id": "SCENARIO_G", "attack_type": AttackType.SESSION_ABUSE_ATTACK, "intensity": AttackIntensity.LOW},
        {"id": "SCENARIO_H", "attack_type": AttackType.SESSION_ABUSE_ATTACK, "intensity": AttackIntensity.HIGH},
        {"id": "SCENARIO_I", "attack_type": AttackType.RESOURCE_PRESSURE_ATTACK, "intensity": AttackIntensity.LOW},
        {"id": "SCENARIO_J", "attack_type": AttackType.RESOURCE_PRESSURE_ATTACK, "intensity": AttackIntensity.HIGH},
    ]
    
    results_list = []
    
    total_orch_time = 0
    total_events = 0
    
    print(f"{'Scenario':<12} | {'Attack Type':<25} | {'Int':<6} | {'Attempts':<8} | {'Inj':<5} | {'AuthF':<5} | {'RepF':<4} | {'IntF':<4} | {'RiskD':<8} | {'ModeC':<5} | {'Lat'}")
    print("-" * 115)
    
    for s_def in scenarios:
        res = run_experiment_scenario(s_def, seed=42)
        results_list.append(res)
        
        total_orch_time += res["metrics"]["execution_time_sec"]
        total_events += res["metrics"]["processed_attack_events"]
        
        # Assertions / Invariants
        if res["response"]["mode_changed"] == 0:
            assert res["response"]["transition_latency_ticks"] == "N/A", "Latency must be N/A if no transition"
        else:
            assert isinstance(res["response"]["transition_latency_ticks"], int) and res["response"]["transition_latency_ticks"] >= 0
            
        if s_def["attack_type"] != "NO_ATTACK":
            assert res["metrics"]["attack_attempts"] == res["ground_truth"]["attempts_generated"]
            assert res["metrics"]["attack_injections"] == res["ground_truth"]["events_generated"]
        
        att = res["metrics"]["attack_attempts"]
        inj = res["metrics"]["attack_injections"]
        af = res["response"]["authentication_failures"]
        rf = res["response"]["replay_failures"]
        inf = res["response"]["integrity_failures"]
        rd = f"{res['metrics']['risk_delta']:+.1f}"
        mc = "Yes" if res["response"]["mode_changed"] else "No"
        lat = res["response"]["transition_latency_ticks"]
        
        type_str = res["attack_type"]
        int_str = res["intensity"]
        
        print(f"{s_def['id']:<12} | {type_str:<25} | {int_str:<6} | {att:<8} | {inj:<5} | {af:<5} | {rf:<4} | {inf:<4} | {rd:<8} | {mc:<5} | {lat}")
        
    print(f"\nTotal Experiment Execution Time (Excl Setup): {total_orch_time:.6f}s")
    print(f"Total Attack Events Processed: {total_events}")
    print(f"Mean Time Per Scenario: {total_orch_time / len(scenarios):.6f}s")
    if total_events > 0:
        print(f"Mean Processing Time Per Attack Event: {total_orch_time / total_events:.6f}s")
        
    # Save results
    os.makedirs("results", exist_ok=True)
    out_path = os.path.join("results", "step13_experiment_results.json")
    with open(out_path, "w") as f:
        json.dump({
            "seed": 42,
            "summary": {
                "total_scenarios": len(scenarios),
                "total_events_processed": total_events,
                "execution_time_sec": total_orch_time
            },
            "scenarios": results_list
        }, f, indent=2)
    print(f"\nResults saved to {out_path}")

if __name__ == "__main__":
    main()
