import time
import statistics
import os
import random
from src.simulator import Simulator
from src.security.environment.manager import EnvironmentManager
from src.security.environment.models import (
    DeviceContext, EdgeContext, CoreContext, SecurityMode, AuthStatus, OperationalState
)
from src.events import EventType

SEED = 42
"""
This script performs a differential overhead benchmark of the Step 7 Environment tracking.

This benchmark measures worst-case synchronous Step 7 context-tracking overhead by creating 
and transitioning a security context for every generated message. It is a stress/upper-bound 
measurement and must not be interpreted as the expected production overhead of a cached 
or session-level environment context.
"""

def run_network_only():
    config_path = os.path.join("configs", "default_network.yaml")
    sim = Simulator(config_path)
    sim.random_seed = SEED
    random.seed(SEED)
    
    start_time = time.time()
    
    sim.initialize_network()
    
    for tick in range(1, sim.duration + 1):
        sim.current_tick = tick
        core_ids = list(sim.network.cores.keys())
        for device in sim.network.devices.values():
            if random.random() < sim.message_rate:
                target_core = sim.network.edges[device.connected_edge_id].connected_core_id
                msg = device.generate_message(
                    target_core_id=target_core,
                    payload={"data": "sensor_reading", "val": random.random()},
                    size=256,
                    timestamp=tick
                )
                sim.logger.log(EventType.MESSAGE_CREATED, tick, message_id=msg.message_id, device_id=device.device_id, target_core_id=target_core)
                sim.total_messages_generated += 1
        sim.network.step(tick)
        
    end_time = time.time()
    return end_time - start_time, 0

def run_with_env():
    config_path = os.path.join("configs", "default_network.yaml")
    sim = Simulator(config_path)
    sim.random_seed = SEED
    random.seed(SEED)
    
    start_time = time.time()
    
    sim.initialize_network()
    
    env = EnvironmentManager()
    
    for core_id in sim.network.cores:
        env.register_core(CoreContext(core_id, OperationalState.ONLINE, [SecurityMode.CLASSICAL, SecurityMode.PQC, SecurityMode.HYBRID]))
    for edge_id, edge in sim.network.edges.items():
        env.register_edge(EdgeContext(edge_id, OperationalState.ONLINE, [SecurityMode.CLASSICAL, SecurityMode.PQC, SecurityMode.HYBRID], edge.connected_core_id))
    for dev_id, dev in sim.network.devices.items():
        env.register_device(DeviceContext(dev_id, dev.device_type, OperationalState.ONLINE, [SecurityMode.CLASSICAL, SecurityMode.PQC, SecurityMode.HYBRID], ["ed25519"], ["mldsa"], dev.connected_edge_id))

    errors = 0
    
    for tick in range(1, sim.duration + 1):
        sim.current_tick = tick
        env.update_tick(tick)
        
        core_ids = list(sim.network.cores.keys())
        for device in sim.network.devices.values():
            if random.random() < sim.message_rate:
                target_core = sim.network.edges[device.connected_edge_id].connected_core_id
                
                # Context tracking
                try:
                    ctx_id = f"ctx_{device.device_id}_{target_core}_{tick}"
                    env.create_communication_context(ctx_id, device.device_id, target_core, SecurityMode.HYBRID)
                    env.update_security_context(ctx_id, auth_status=AuthStatus.AUTHENTICATING)
                    env.update_security_context(ctx_id, auth_status=AuthStatus.AUTHENTICATED, encryption_active=True, session_id=f"ses_{tick}")
                except Exception as e:
                    errors += 1
                    
                msg = device.generate_message(
                    target_core_id=target_core,
                    payload={"data": "sensor_reading", "val": random.random()},
                    size=256,
                    timestamp=tick
                )
                sim.logger.log(EventType.MESSAGE_CREATED, tick, message_id=msg.message_id, device_id=device.device_id, target_core_id=target_core)
                sim.total_messages_generated += 1
        sim.network.step(tick)
        
    end_time = time.time()
    return end_time - start_time, errors

def main():
    trials = 3
    net_times = []
    env_times = []
    total_errors = 0
    
    for _ in range(trials):
        t, e = run_network_only()
        net_times.append(t)
        
    for _ in range(trials):
        t, e = run_with_env()
        env_times.append(t)
        total_errors += e
        
    net_mean = statistics.mean(net_times)
    env_mean = statistics.mean(env_times)
    
    print("--- Differential Overhead Benchmark ---")
    print("NOTE: This benchmark measures worst-case synchronous Step 7 context-tracking overhead")
    print("by creating and transitioning a security context for every generated message.")
    print("It is a stress/upper-bound measurement and must not be interpreted as the expected")
    print("production overhead of a cached or session-level environment context.\n")
    print(f"Network-only runtime:")
    print(f"  Mean: {net_mean:.4f}s")
    print(f"  Min:  {min(net_times):.4f}s")
    print(f"  Max:  {max(net_times):.4f}s")
    print(f"  Stdev:{statistics.stdev(net_times) if trials > 1 else 0:.4f}s")
    
    print(f"\nEnvironment-enabled runtime:")
    print(f"  Mean: {env_mean:.4f}s")
    print(f"  Min:  {min(env_times):.4f}s")
    print(f"  Max:  {max(env_times):.4f}s")
    print(f"  Stdev:{statistics.stdev(env_times) if trials > 1 else 0:.4f}s")
    
    absolute_overhead = env_mean - net_mean
    pct_overhead = (absolute_overhead / net_mean) * 100 if net_mean > 0 else 0
    
    print(f"\nAbsolute overhead: {absolute_overhead:.4f}s")
    print(f"Percentage overhead: {pct_overhead:.2f}%")
    print(f"\nUnexpected errors: {total_errors}")

if __name__ == '__main__':
    main()
