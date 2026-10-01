import os
import json
import time
import random
from src.simulator import Simulator
from src.events import EventLogger
from src.security.manager import SecurityManager, ProtectedMessagePayload
from src.security.attacker import (
    AttackerSimulator, AttackerProfile, AttackScenario,
    AttackType, AttackIntensity, AttackGroundTruth
)

def run_experiment(seed=42):
    random.seed(seed)
    
    config_path = os.path.join("configs", "default_network.yaml")
    sim = Simulator(config_path)
    sim.initialize_network()
    
    logger = EventLogger()
    sec_manager = SecurityManager(logger)
    
    entities = list(sim.network.devices.keys()) + list(sim.network.edges.keys()) + list(sim.network.cores)
    
    for e in entities:
        sec_manager.register_device(e)
        
    attacker_sim = AttackerSimulator(sec_manager, logger, seed=seed)
    attacker_sim.set_environment(entities, ["ctx_1", "ctx_2", "ctx_3", "ctx_4"])
    
    # Profiles
    p1 = AttackerProfile("attacker_A", [AttackType.AUTHENTICATION_ATTACK, AttackType.REPLAY_ATTACK, AttackType.MESSAGE_TAMPERING_ATTACK], AttackIntensity.HIGH)
    p2 = AttackerProfile("attacker_B", [AttackType.SESSION_ABUSE_ATTACK, AttackType.RESOURCE_PRESSURE_ATTACK], AttackIntensity.MEDIUM)
    attacker_sim.scheduler.register_attacker(p1)
    attacker_sim.scheduler.register_attacker(p2)
    
    # Target entities
    dev1 = entities[0]
    dev2 = entities[1]
    
    # Scenarios (overlapping: 20-30 and 25-35)
    s1 = AttackScenario("atk_01", AttackType.AUTHENTICATION_ATTACK, "attacker_A", dev1, "ctx_1", 10, 5, AttackIntensity.LOW)
    s2 = AttackScenario("atk_02", AttackType.REPLAY_ATTACK, "attacker_A", dev2, "ctx_2", 20, 10, AttackIntensity.MEDIUM)
    s3 = AttackScenario("atk_03", AttackType.MESSAGE_TAMPERING_ATTACK, "attacker_A", dev1, "ctx_3", 25, 10, AttackIntensity.MEDIUM)
    s4 = AttackScenario("atk_04", AttackType.SESSION_ABUSE_ATTACK, "attacker_B", dev1, "ctx_4", 40, 5, AttackIntensity.HIGH)
    s5 = AttackScenario("atk_05", AttackType.RESOURCE_PRESSURE_ATTACK, "attacker_B", dev2, "ctx_1", 50, 5, AttackIntensity.HIGH)
    
    attacker_sim.schedule_attack(s1)
    attacker_sim.schedule_attack(s2)
    attacker_sim.schedule_attack(s3)
    attacker_sim.schedule_attack(s4)
    attacker_sim.schedule_attack(s5)
    
    start_time = time.perf_counter()
    
    total_events = 0
    injection_errors = 0
    
    genuine_totals = {"AUTHENTICATION_ATTACK": 0, "REPLAY_ATTACK": 0, "MESSAGE_TAMPERING_ATTACK": 0, "SESSION_ABUSE_ATTACK": 0, "RESOURCE_PRESSURE_ATTACK": 0}
    synthetic_totals = {"AUTHENTICATION_ATTACK": 0, "REPLAY_ATTACK": 0, "MESSAGE_TAMPERING_ATTACK": 0, "SESSION_ABUSE_ATTACK": 0, "RESOURCE_PRESSURE_ATTACK": 0}
    
    for tick in range(1, 100):
        # Simulate some normal traffic to capture
        if tick % 10 == 0:
            sec_manager.authenticate_and_exchange(dev1, dev2, tick)
            try:
                payload = sec_manager.encrypt_message(dev1, dev2, {"data": "test"}, tick)
                attacker_sim.capture_message(dev1, dev2, payload)
            except Exception:
                pass
                
        results = attacker_sim.process_tick(tick)
        for r in results:
            injection_errors += len(r.injection_errors)
            typ_name = None
            for s in [s1, s2, s3, s4, s5]:
                if s.attack_id == r.attack_id:
                    typ_name = s.attack_type.value
                    break
            if typ_name and typ_name in genuine_totals:
                genuine_totals[typ_name] += r.genuine_attempts
                synthetic_totals[typ_name] += r.synthetic_attempts
            
    end_time = time.perf_counter()
    exec_time = end_time - start_time
    
    # Calculate total_events from the ground truths canonical source
    total_events = sum(gt.events_generated for gt in attacker_sim.ground_truths.values())
    
    # Collect stats
    return {
        "network_size": len(entities),
        "profiles": 2,
        "scenarios": 5,
        "attack_types": 5,
        "total_events": total_events,
        "injection_errors": injection_errors,
        "genuine_totals": genuine_totals,
        "synthetic_totals": synthetic_totals,
        "exec_time": exec_time,
        "ground_truths": [gt.to_dict() for gt in attacker_sim.ground_truths.values()],
        "logger": logger
    }

def main():
    print("Starting AERIS-PQ6G Attacker Simulation Baseline...")
    
    res = run_experiment(42)
    
    print("\n--- Network ---")
    print(f"Network Size (Entities): {res['network_size']}")
    
    print("\n--- Attacker Profiles ---")
    print(f"Profiles Registered: {res['profiles']}")
    print(f"Attack Types Available: {res['attack_types']}")
    
    print("\n--- Scenarios ---")
    print(f"Scenarios Scheduled: {res['scenarios']}")
    
    print("\n--- Ground Truth Summary ---")
    attacks_by_ctx = {}
    attacks_by_target = {}
    events_per_type = {}
    events_per_intensity = {}
    scenarios_per_intensity = {}
    
    for gt in res['ground_truths']:
        ctx = gt['context_id']
        tgt = gt['target_id']
        typ = gt['attack_type']
        intense = gt['intended_intensity']
        evts = gt['events_generated']
        
        attacks_by_ctx[ctx] = attacks_by_ctx.get(ctx, 0) + 1
        attacks_by_target[tgt] = attacks_by_target.get(tgt, 0) + 1
        events_per_type[typ] = events_per_type.get(typ, 0) + evts
        events_per_intensity[intense] = events_per_intensity.get(intense, 0) + evts
        scenarios_per_intensity[intense] = scenarios_per_intensity.get(intense, 0) + 1
        
    print(f"Total Attack Events: {res['total_events']}")
    print(f"Injection Errors: {res['injection_errors']}")
    
    # Reconciliation assertions
    total_from_types = sum(events_per_type.values())
    total_from_intensities = sum(events_per_intensity.values())
    assert total_from_types == res['total_events'], f"Type mismatch: {total_from_types} != {res['total_events']}"
    assert total_from_intensities == res['total_events'], f"Intensity mismatch: {total_from_intensities} != {res['total_events']}"
    assert res['total_events'] == 356, f"Expected 356 events, got {res['total_events']}"
    
    print("\nEvents per Attack Type:")
    for k, v in events_per_type.items(): print(f"  {k}: {v}")
    
    print("\nEvents per Intensity:")
    for k, v in events_per_intensity.items(): print(f"  {k} = {v}")
    
    print("\nScenarios per Intensity:")
    for k, v in scenarios_per_intensity.items(): print(f"  {k} scenarios = {v}")
    
    print("\nAttacks by Context:")
    for k, v in attacks_by_ctx.items(): print(f"  {k}: {v}")
    
    print("\nAttacks by Target:")
    for k, v in attacks_by_target.items(): print(f"  {k}: {v}")
    
    print("\nComplete Ground Truth Records:")
    print(json.dumps(res['ground_truths'], indent=2))
    
    logger = res["logger"]
    events = logger.get_events()
    event_types_count = {}
    for e in events:
        et = e["event_type"]
        event_types_count[et] = event_types_count.get(et, 0) + 1
        
    print("\n--- Event Types Summary ---")
    for k, v in event_types_count.items():
        if k.startswith("ATTACK_"):
            print(f"  {k}: {v}")
            
    print("\n--- Genuine vs Synthetic Attack Inputs ---")
    gen = res["genuine_totals"]
    syn = res["synthetic_totals"]
    print(f"Replay:")
    print(f"  genuine captured-message replays = {gen['REPLAY_ATTACK']}")
    print(f"  synthetic fallback replays = {syn['REPLAY_ATTACK']}")
    print(f"Tampering:")
    print(f"  genuine captured-message tampering = {gen['MESSAGE_TAMPERING_ATTACK']}")
    print(f"  synthetic fallback tampering = {syn['MESSAGE_TAMPERING_ATTACK']}")
    print(f"Authentication:")
    print(f"  real authentication-boundary attempts = {gen['AUTHENTICATION_ATTACK']}")
    print(f"Session abuse:")
    print(f"  real environment/session-boundary attempts = {gen['SESSION_ABUSE_ATTACK']}")
    print(f"Resource pressure:")
    print(f"  actual simulator-generated bounded requests = {syn['RESOURCE_PRESSURE_ATTACK']}")

    print(f"\nExecution Time (s): {res['exec_time']:.6f}")
    
    # Reproducibility check
    res2 = run_experiment(42)
    if res['ground_truths'] == res2['ground_truths']:
        print("\nReproducibility Check: PASS (Exact Match)")
    else:
        print("\nReproducibility Check: FAIL")

if __name__ == "__main__":
    main()
