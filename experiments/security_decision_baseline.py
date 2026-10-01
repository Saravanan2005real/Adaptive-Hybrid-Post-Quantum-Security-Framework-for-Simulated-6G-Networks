import time
import os
import random
import statistics
from src.simulator import Simulator
from src.security.environment.manager import EnvironmentManager
from src.security.environment.models import (
    DeviceContext, EdgeContext, CoreContext, SecurityMode, AuthStatus, OperationalState, EnvironmentEventType
)
from src.security.risk.manager import RiskManager
from src.security.decision.engine import DecisionEngine
from src.events import EventLogger

SEED = 42

def setup_healthy_context(env, dev_id, core_id, mode=SecurityMode.CLASSICAL):
    ctx_id = f"ctx_{dev_id}_{core_id}"
    env.create_communication_context(ctx_id, dev_id, core_id, mode)
    env.update_security_context(ctx_id, auth_status=AuthStatus.AUTHENTICATING)
    env.update_security_context(ctx_id, auth_status=AuthStatus.AUTHENTICATED, encryption_active=True, session_id=f"ses_{ctx_id}")
    return ctx_id

def main():
    print("Starting AERIS-PQ6G Security Decision Baseline...")
    random.seed(SEED)
    
    config_path = os.path.join("configs", "default_network.yaml")
    sim = Simulator(config_path)
    sim.random_seed = SEED
    sim.initialize_network()
    
    env = EnvironmentManager()
    logger = EventLogger()
    risk_mgr = RiskManager(env, logger)
    decision_engine = DecisionEngine(logger)
    
    for core_id in sim.network.cores:
        env.register_core(CoreContext(core_id, OperationalState.ONLINE, [SecurityMode.CLASSICAL, SecurityMode.PQC, SecurityMode.HYBRID]))
    for edge_id, edge in sim.network.edges.items():
        env.register_edge(EdgeContext(edge_id, OperationalState.ONLINE, [SecurityMode.CLASSICAL, SecurityMode.PQC, SecurityMode.HYBRID], edge.connected_core_id))
    
    devices = list(sim.network.devices.values())
    for dev in devices:
        env.register_device(DeviceContext(dev.device_id, dev.device_type, OperationalState.ONLINE, [SecurityMode.CLASSICAL, SecurityMode.PQC, SecurityMode.HYBRID], ["ed25519"], ["mldsa"], dev.connected_edge_id))
        
    contexts = []
    scenarios = []

    # Scenario A: LOW risk, current CLASSICAL -> recommend CLASSICAL, no transition
    dev_a = devices[0]
    core_a = sim.network.edges[dev_a.connected_edge_id].connected_core_id
    ctx_a = setup_healthy_context(env, dev_a.device_id, core_a, SecurityMode.HYBRID)
    # Actually wait, Scenario A needs LOW risk and current CLASSICAL.
    # The prompt says: "Scenario A: LOW risk, current CLASSICAL, recommendation CLASSICAL".
    # Wait, if mode=CLASSICAL, risk might be non-zero because of the MODE_CLASSICAL penalty (10.0), 
    # but 10.0 is still LOW risk.
    env.update_security_context(ctx_a, security_mode=SecurityMode.CLASSICAL)
    contexts.append(ctx_a)
    scenarios.append(("Scenario A", ctx_a))
    
    # Scenario B: MEDIUM risk, current CLASSICAL -> recommend PQC, transition required
    dev_b = devices[1]
    core_b = sim.network.edges[dev_b.connected_edge_id].connected_core_id
    ctx_b = setup_healthy_context(env, dev_b.device_id, core_b, SecurityMode.CLASSICAL)
    env.telemetry.record(1, EnvironmentEventType.AUTHENTICATION_FAILED.value, ctx_b, dev_b.device_id, {})
    env.telemetry.record(2, EnvironmentEventType.AUTHENTICATION_FAILED.value, ctx_b, dev_b.device_id, {})
    contexts.append(ctx_b)
    scenarios.append(("Scenario B", ctx_b))
    
    # Scenario C: HIGH risk, current CLASSICAL -> recommend HYBRID, transition required
    dev_c = devices[2]
    core_c = sim.network.edges[dev_c.connected_edge_id].connected_core_id
    ctx_c = setup_healthy_context(env, dev_c.device_id, core_c, SecurityMode.CLASSICAL)
    # CLASSICAL (+10) + Encryption Disabled (+40) = 50.0 (HIGH)
    env.update_security_context(ctx_c, encryption_active=False)
    contexts.append(ctx_c)
    scenarios.append(("Scenario C", ctx_c))

    # Scenario D: CRITICAL risk, current PQC -> recommend HYBRID, transition required
    dev_d = devices[3]
    core_d = sim.network.edges[dev_d.connected_edge_id].connected_core_id
    ctx_d = setup_healthy_context(env, dev_d.device_id, core_d, SecurityMode.PQC)
    env.update_security_context(ctx_d, encryption_active=False, session_id=None)
    env.update_entity_state(dev_d.device_id, OperationalState.COMPROMISED)
    contexts.append(ctx_d)
    scenarios.append(("Scenario D", ctx_d))

    # Scenario E: HIGH risk, current HYBRID -> recommend HYBRID, no transition
    dev_e = devices[4]
    core_e = sim.network.edges[dev_e.connected_edge_id].connected_core_id
    ctx_e = setup_healthy_context(env, dev_e.device_id, core_e, SecurityMode.HYBRID)
    env.update_security_context(ctx_e, encryption_active=False, session_id=None)
    contexts.append(ctx_e)
    scenarios.append(("Scenario E", ctx_e))

    for i in range(5, len(devices)):
        dev_n = devices[i]
        core_n = sim.network.edges[dev_n.connected_edge_id].connected_core_id
        ctx_n = setup_healthy_context(env, dev_n.device_id, core_n, SecurityMode.CLASSICAL)
        contexts.append(ctx_n)

    print("--- Controlled Scenarios ---")
    for name, ctx_id in scenarios:
        # Need to calculate risk for context + entity
        ctx_risk = risk_mgr.evaluate_context(ctx_id)
        ent_id = env.comm_contexts[ctx_id].source_id
        ent_risk = risk_mgr.evaluate_entity(ent_id)
        
        # Merge score to pass to engine, matching Step 8
        total_score = min(100.0, ctx_risk.risk_score + ent_risk.risk_score)
        from src.security.risk.scorer import determine_risk_level
        total_level = determine_risk_level(total_score)
        
        # Create composite assessment
        from src.security.risk.models import RiskAssessment
        composite_assessment = RiskAssessment(
            entity_id=ent_id,
            risk_score=total_score,
            risk_level=total_level,
            factors=ctx_risk.factors + ent_risk.factors,
            timestamp=env.current_tick
        )
        
        current_mode = env.comm_contexts[ctx_id].security.security_mode
        decision = decision_engine.evaluate_decision(composite_assessment, current_mode, ctx_id)
        
        print(f"{name}:")
        print(f"  Risk Score: {decision.risk_score:.1f}")
        print(f"  Risk Level: {decision.risk_level.name}")
        print(f"  Current Mode: {decision.current_security_mode.name}")
        print(f"  Recommended Mode: {decision.recommended_security_mode.name}")
        print(f"  Transition Required: {decision.requires_transition}")
        print(f"  Policy Rule: {decision.policy_rule}")
        print(f"  Decision Reason: {decision.decision_reason}")
        print()
        
    print("--- Performance Measurement ---")
    start_time = time.perf_counter()
    
    decision_times = []
    
    for ctx_id in contexts:
        ent_id = env.comm_contexts[ctx_id].source_id
        ctx_risk = risk_mgr.evaluate_context(ctx_id)
        ent_risk = risk_mgr.evaluate_entity(ent_id)
        total_score = min(100.0, ctx_risk.risk_score + ent_risk.risk_score)
        from src.security.risk.scorer import determine_risk_level
        total_level = determine_risk_level(total_score)
        
        from src.security.risk.models import RiskAssessment
        composite_assessment = RiskAssessment(
            entity_id=ent_id,
            risk_score=total_score,
            risk_level=total_level,
            factors=[],
            timestamp=env.current_tick
        )
        
        current_mode = env.comm_contexts[ctx_id].security.security_mode
        
        # Measure ONLY decision engine
        t0 = time.perf_counter()
        decision_engine.evaluate_decision(composite_assessment, current_mode, ctx_id)
        t1 = time.perf_counter()
        
        decision_times.append(t1 - t0)

    total_runtime = time.perf_counter() - start_time
    
    print(f"Security Decision Engine Evaluation Time")
    print(f"Total Decisions: {len(contexts)}")
    print(f"Mean Decision Time: {statistics.mean(decision_times):.6f}s")
    print(f"Minimum Decision Time: {min(decision_times):.6f}s")
    print(f"Maximum Decision Time: {max(decision_times):.6f}s")
    print(f"Total Runtime: {total_runtime:.6f}s")

if __name__ == '__main__':
    main()
