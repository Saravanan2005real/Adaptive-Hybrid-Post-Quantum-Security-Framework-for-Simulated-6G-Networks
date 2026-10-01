import os
import json
import time
import random
import traceback
from src.simulator import Simulator
from src.security.hybrid_auth.protocol import HybridAuthProtocol
from src.events import EventType

def main():
    print("Starting AERIS-PQ6G Hybrid Authentication Baseline Simulation...")
    config_path = os.path.join("configs", "default_network.yaml")
    
    sim = Simulator(config_path)
    sim.initialize_network()
    
    auth_prot = HybridAuthProtocol(sim.logger)
    
    for dev_id in sim.network.devices:
        auth_prot.register_device(dev_id)
    for core_id in sim.network.cores:
        auth_prot.register_device(core_id)
        
    start_time = time.time()
    
    exception_counts = {}
    
    for tick in range(1, sim.duration + 1):
        sim.current_tick = tick
        for device in sim.network.devices.values():
            if random.random() < sim.message_rate:
                edge = sim.network.edges.get(device.connected_edge_id)
                if not edge or not edge.connected_core_id:
                    continue
                target_core = edge.connected_core_id
                
                try:
                    req = auth_prot.create_request(device.device_id, target_core)
                    chal = auth_prot.issue_challenge(req, target_core)
                    resp_init = auth_prot.respond_to_challenge(chal, device.device_id)
                    resp_resp = auth_prot.verify_initiator_response(resp_init, target_core)
                    auth_prot.verify_responder_response(resp_resp, device.device_id)
                except Exception as e:
                    exc_str = str(e) or type(e).__name__
                    exception_counts[exc_str] = exception_counts.get(exc_str, 0) + 1
                
    end_time = time.time()
    exec_time = end_time - start_time
    
    print("\n--- Authentication Simulation Summary ---")
    print(f"Total Authentication Attempts: {auth_prot.metrics['authentication_attempts']}")
    print(f"Successful Authentications: {auth_prot.metrics['successful_authentications']}")
    print(f"Failed Authentications: {auth_prot.metrics['failed_authentications']}")
    print(f"Protocol Rejections: {auth_prot.metrics['protocol_rejections']}")
    print(f"Classical Sig Failures: {auth_prot.metrics['classical_signature_failures']}")
    print(f"PQC Sig Failures: {auth_prot.metrics['pqc_signature_failures']}")
    print(f"Expired Challenges: {auth_prot.metrics['expired_challenges']}")
    print(f"Replayed Challenges: {auth_prot.metrics['replayed_challenges']}")
    
    print("\n--- Exception Counts ---")
    if not exception_counts:
        print("None")
    for exc, count in exception_counts.items():
        print(f"{exc}: {count}")
        
    avg_lat = 0.0
    if auth_prot.metrics['authentication_attempts'] > 0:
        avg_lat = auth_prot.metrics['authentication_latency'] / auth_prot.metrics['authentication_attempts']
        
    print(f"\nAverage Auth Latency (ms): {avg_lat:.4f}")
    print(f"Total Auth Latency (ms): {auth_prot.metrics['authentication_latency']:.4f}")
    print(f"Simulation Execution Time (s): {exec_time:.4f}")

    results_dir = "results"
    os.makedirs(results_dir, exist_ok=True)
    events_file = os.path.join(results_dir, "hybrid_auth_events.json")
    
    with open(events_file, "w") as f:
        json.dump(sim.logger.get_events(), f, indent=2)
        
    print(f"\nEvent log saved to {events_file}")

if __name__ == "__main__":
    main()
