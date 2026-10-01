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
from src.security.risk.models import RiskLevel
from src.events import EventLogger

SEED = 42

def setup_healthy_context(env, dev_id, core_id):
    ctx_id = f"ctx_{dev_id}_{core_id}"
    env.create_communication_context(ctx_id, dev_id, core_id, SecurityMode.HYBRID)
    env.update_security_context(ctx_id, auth_status=AuthStatus.AUTHENTICATING)
    env.update_security_context(ctx_id, auth_status=AuthStatus.AUTHENTICATED, encryption_active=True, session_id=f"ses_{ctx_id}")
    return ctx_id

def main():
    print("Starting AERIS-PQ6G Security Risk Baseline...")
    random.seed(SEED)
    
    config_path = os.path.join("configs", "default_network.yaml")
    sim = Simulator(config_path)
    sim.random_seed = SEED
    sim.initialize_network()
    
    env = EnvironmentManager()
    logger = EventLogger()
    risk_mgr = RiskManager(env, logger)
    
    print(f"Random Seed: {SEED}\n")
    
    for core_id in sim.network.cores:
        env.register_core(CoreContext(core_id, OperationalState.ONLINE, [SecurityMode.CLASSICAL, SecurityMode.PQC, SecurityMode.HYBRID]))
    for edge_id, edge in sim.network.edges.items():
        env.register_edge(EdgeContext(edge_id, OperationalState.ONLINE, [SecurityMode.CLASSICAL, SecurityMode.PQC, SecurityMode.HYBRID], edge.connected_core_id))
    
    devices = list(sim.network.devices.values())
    for dev in devices:
        env.register_device(DeviceContext(dev.device_id, dev.device_type, OperationalState.ONLINE, [SecurityMode.CLASSICAL, SecurityMode.PQC, SecurityMode.HYBRID], ["ed25519"], ["mldsa"], dev.connected_edge_id))
        
    contexts = []
    
    # Scenario A: Healthy online entity (HYBRID, Auth, Encrypted, Online)
    dev_a = devices[0]
    core_a = sim.network.edges[dev_a.connected_edge_id].connected_core_id
    ctx_a = setup_healthy_context(env, dev_a.device_id, core_a)
    contexts.append(ctx_a)
    
    # Scenario B: Authentication failures
    dev_b = devices[1]
    core_b = sim.network.edges[dev_b.connected_edge_id].connected_core_id
    ctx_b = setup_healthy_context(env, dev_b.device_id, core_b)
    env.telemetry.record(1, EnvironmentEventType.AUTHENTICATION_FAILED.value, ctx_b, dev_b.device_id, {})
    env.telemetry.record(2, EnvironmentEventType.AUTHENTICATION_FAILED.value, ctx_b, dev_b.device_id, {})
    contexts.append(ctx_b)
    
    # Scenario C: Encryption disabled
    dev_c = devices[2]
    core_c = sim.network.edges[dev_c.connected_edge_id].connected_core_id
    ctx_c = setup_healthy_context(env, dev_c.device_id, core_c)
    env.update_security_context(ctx_c, encryption_active=False)
    contexts.append(ctx_c)
    
    # Scenario D: No active session
    dev_d = devices[3]
    core_d = sim.network.edges[dev_d.connected_edge_id].connected_core_id
    ctx_d = setup_healthy_context(env, dev_d.device_id, core_d)
    env.update_security_context(ctx_d, encryption_active=False, session_id=None)
    contexts.append(ctx_d)
    
    # Scenario E: Degraded operational state
    dev_e = devices[4]
    core_e = sim.network.edges[dev_e.connected_edge_id].connected_core_id
    ctx_e = setup_healthy_context(env, dev_e.device_id, core_e)
    env.update_entity_state(dev_e.device_id, OperationalState.DEGRADED)
    contexts.append(ctx_e)
    
    # Scenario F: Compromised entity
    dev_f = devices[5]
    core_f = sim.network.edges[dev_f.connected_edge_id].connected_core_id
    ctx_f = setup_healthy_context(env, dev_f.device_id, core_f)
    env.update_entity_state(dev_f.device_id, OperationalState.COMPROMISED)
    contexts.append(ctx_f)
    
    # Scenario G: Multiple simultaneous risk factors (Intentionally compounded scenario)
    dev_g = devices[6]
    core_g = sim.network.edges[dev_g.connected_edge_id].connected_core_id
    ctx_g = setup_healthy_context(env, dev_g.device_id, core_g)
    env.update_security_context(ctx_g, security_mode=SecurityMode.CLASSICAL)
    env.update_security_context(ctx_g, encryption_active=False, session_id=None)
    env.update_entity_state(dev_g.device_id, OperationalState.DEGRADED)
    contexts.append(ctx_g)
    
    # Random load for performance
    for i in range(7, len(devices)):
        dev_n = devices[i]
        core_n = sim.network.edges[dev_n.connected_edge_id].connected_core_id
        ctx_n = setup_healthy_context(env, dev_n.device_id, core_n)
        contexts.append(ctx_n)

    # 5. Evaluate risk
    print("--- Controlled Scenarios ---")
    scenarios = [
        ("Scenario A (Healthy)", ctx_a),
        ("Scenario B (Auth Failures)", ctx_b),
        ("Scenario C (Encryption Disabled)", ctx_c),
        ("Scenario D (No Session)", ctx_d),
        ("Scenario E (Degraded State)", ctx_e),
        ("Scenario F (Compromised Entity)", ctx_f),
        ("Scenario G (Multiple Factors)", ctx_g)
    ]
    
    for name, ctx_id in scenarios:
        risk_ctx = risk_mgr.evaluate_context(ctx_id)
        ent_id = env.comm_contexts[ctx_id].source_id
        risk_ent = risk_mgr.evaluate_entity(ent_id)
        
        print(f"{name}:")
        print("  CONTEXT RISK:")
        print(f"    Score: {risk_ctx.risk_score:.1f}, Level: {risk_ctx.risk_level.value}")
        for f in risk_ctx.factors:
            print(f"    - {f.name}: +{f.contribution:.1f} ({f.evidence})")
            
        print("  ENTITY RISK:")
        print(f"    Score: {risk_ent.risk_score:.1f}, Level: {risk_ent.risk_level.value}")
        for f in risk_ent.factors:
            print(f"    - {f.name}: +{f.contribution:.1f} ({f.evidence})")
        
        total_score = min(100.0, risk_ctx.risk_score + risk_ent.risk_score)
        from src.security.risk.scorer import determine_risk_level
        print(f"  COMBINED TOTAL:")
        print(f"    Score: {total_score:.1f}, Level: {determine_risk_level(total_score).value}")
        print()
        
    print("--- Performance Measurement ---")
    start_time = time.perf_counter()
    
    context_eval_times = []
    entity_eval_times = []
    invalid_evaluations = 0
    
    for ctx_id in contexts:
        source_id = env.comm_contexts[ctx_id].source_id
        
        ctx_t0 = time.perf_counter()
        try:
            r = risk_mgr.evaluate_context(ctx_id)
        except Exception:
            invalid_evaluations += 1
        ctx_t1 = time.perf_counter()
        context_eval_times.append(ctx_t1 - ctx_t0)
        
        ent_t0 = time.perf_counter()
        try:
            e = risk_mgr.evaluate_entity(source_id)
        except Exception:
            invalid_evaluations += 1
        ent_t1 = time.perf_counter()
        entity_eval_times.append(ent_t1 - ent_t0)

    total_runtime = time.perf_counter() - start_time
    
    print(f"Total Context Evaluations: {len(contexts)}")
    print(f"Total Entity Evaluations: {len(contexts)}")
    print(f"Total Baseline Runtime: {total_runtime:.6f}s")
    
    print("\nContext Evaluation Times:")
    print(f"  Mean: {statistics.mean(context_eval_times):.6f}s")
    print(f"  Min:  {min(context_eval_times):.6f}s")
    print(f"  Max:  {max(context_eval_times):.6f}s")
    
    print("\nEntity Evaluation Times:")
    print(f"  Mean: {statistics.mean(entity_eval_times):.6f}s")
    print(f"  Min:  {min(entity_eval_times):.6f}s")
    print(f"  Max:  {max(entity_eval_times):.6f}s")
    
    print(f"\nRejected/Invalid Evaluations: {invalid_evaluations}")

if __name__ == '__main__':
    main()
