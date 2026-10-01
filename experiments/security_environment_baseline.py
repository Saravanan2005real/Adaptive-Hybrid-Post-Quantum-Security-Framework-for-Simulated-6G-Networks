import os
import json
import time
import random
from src.simulator import Simulator
from src.security.environment.manager import EnvironmentManager
from src.security.environment.models import (
    DeviceContext, EdgeContext, CoreContext, SecurityMode, AuthStatus, OperationalState
)

def main():
    print("Starting AERIS-PQ6G Security Environment Baseline...")
    print("Authentication states in this Step 7 baseline are synthetic context states used to exercise the environment layer. They do not execute the Step 3–6 authentication protocols.")
    
    SEED = 42
    random.seed(SEED)
    print(f"Random Seed: {SEED}")
    
    config_path = os.path.join("configs", "default_network.yaml")
    
    sim = Simulator(config_path)
    sim.initialize_network()
    
    env = EnvironmentManager()
    
    start_time = time.time()
    
    # Register cores
    for core_id in sim.network.cores:
        env.register_core(CoreContext(core_id, OperationalState.ONLINE, [SecurityMode.CLASSICAL, SecurityMode.PQC, SecurityMode.HYBRID]))
        
    # Register edges
    for edge_id, edge in sim.network.edges.items():
        env.register_edge(EdgeContext(edge_id, OperationalState.ONLINE, [SecurityMode.CLASSICAL, SecurityMode.PQC, SecurityMode.HYBRID], edge.connected_core_id))
        
    # Register devices
    for dev_id, dev in sim.network.devices.items():
        env.register_device(DeviceContext(dev_id, dev.device_type, OperationalState.ONLINE, [SecurityMode.CLASSICAL, SecurityMode.PQC, SecurityMode.HYBRID], ["ed25519"], ["mldsa"], dev.connected_edge_id))

    invalid_ops = 0
    
    for tick in range(1, sim.duration + 1):
        env.update_tick(tick)
        for dev_id, dev in sim.network.devices.items():
            if random.random() < sim.message_rate:
                edge = sim.network.edges.get(dev.connected_edge_id)
                if not edge or not edge.connected_core_id:
                    continue
                target_core = edge.connected_core_id
                ctx_id = f"ctx_{dev_id}_{target_core}_{tick}"
                
                try:
                    mode = random.choice(list(SecurityMode))
                    env.create_communication_context(ctx_id, dev_id, target_core, mode)
                    
                    env.update_security_context(ctx_id, auth_status=AuthStatus.AUTHENTICATING)
                    
                    if random.random() > 0.1:
                        env.update_security_context(ctx_id, auth_status=AuthStatus.AUTHENTICATED, encryption_active=True, session_id=f"ses_{tick}")
                    else:
                        env.update_security_context(ctx_id, auth_status=AuthStatus.FAILED)
                        
                    # randomly change operational state sometimes
                    if random.random() > 0.99:
                        env.update_entity_state(dev_id, OperationalState.COMPROMISED)
                        
                except Exception as e:
                    invalid_ops += 1

    end_time = time.time()
    exec_time = end_time - start_time
    
    snap = env.get_snapshot()
    
    print("\n--- Security Environment Statistics ---")
    print(f"Devices Registered: {len(snap['devices'])}")
    print(f"Edge Nodes Registered: {len(snap['edges'])}")
    print(f"Core Nodes Registered: {len(snap['cores'])}")
    print(f"Communication Contexts: {len(snap['communication_contexts'])}")
    
    auth_states = {}
    sec_modes = {}
    for c in snap['communication_contexts'].values():
        ast = c['security']['auth_status']
        sm = c['security']['security_mode']
        auth_states[ast] = auth_states.get(ast, 0) + 1
        sec_modes[sm] = sec_modes.get(sm, 0) + 1
        
    print("\nContexts by authentication state:")
    for k, v in auth_states.items():
        print(f"  {k}: {v}")
        
    print("\nContexts by security mode:")
    for k, v in sec_modes.items():
        print(f"  {k}: {v}")

    op_states = {}
    for d in snap['devices'].values():
        op_states[d['operational_state']] = op_states.get(d['operational_state'], 0) + 1
    print("\nDevices by operational state:")
    for k, v in op_states.items():
        print(f"  {k}: {v}")

    print(f"\nActive Sessions: {len([c for c in snap['communication_contexts'].values() if c['security']['session_id'] is not None])}")
    
    print("\nTelemetry event counts by event type:")
    telem_counts = {}
    for r in env.telemetry.records:
        telem_counts[r.event_type] = telem_counts.get(r.event_type, 0) + 1
    for k, v in telem_counts.items():
        print(f"  {k}: {v}")
        
    print(f"\nInvalid Operations Detected: {invalid_ops}")
    print(f"Execution Time (s): {exec_time:.4f}")

    results_dir = "results"
    os.makedirs(results_dir, exist_ok=True)
    snap_file = os.path.join(results_dir, "environment_snapshot.json")
    
    try:
        with open(snap_file, "w") as f:
            json.dump(snap, f, indent=2)
        print("Snapshot serialization success: True")
    except Exception as e:
        print(f"Snapshot serialization success: False ({e})")
        
    print(f"\nEnvironment snapshot saved to {snap_file}")

if __name__ == "__main__":
    main()
