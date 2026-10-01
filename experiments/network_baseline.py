import os
import json
import time
from src.simulator import Simulator

def main():
    print("Starting AERIS-PQ6G Network Baseline Simulation...")
    config_path = os.path.join("configs", "default_network.yaml")
    
    start_time = time.time()
    
    sim = Simulator(config_path)
    sim.run()
    
    end_time = time.time()
    exec_time = end_time - start_time
    
    stats = sim.get_summary()
    
    print("\n--- Simulation Summary ---")
    print(f"Number of Devices: {stats['total_devices']}")
    print(f"Number of Edge Nodes: {stats['total_edges']}")
    print(f"Number of Core Nodes: {stats['total_cores']}")
    print(f"Total Messages Generated: {stats['total_messages_generated']}")
    print(f"Successfully Delivered Responses: {stats['total_delivered_responses']}")
    print(f"Failed Messages: {stats['total_failed_messages']}")
    print(f"In-Flight Messages: {stats.get('in_flight_messages', 0)}")
    print(f"Average Response Latency (ticks): {stats['average_response_latency_ticks']:.2f}")
    print(f"Throughput (responses/tick): {stats['throughput_msgs_per_tick']:.2f}")
    print(f"Simulation Execution Time (s): {exec_time:.4f}")

    # Save events
    results_dir = "results"
    os.makedirs(results_dir, exist_ok=True)
    events_file = os.path.join(results_dir, "baseline_events.json")
    
    with open(events_file, "w") as f:
        json.dump(sim.logger.get_events(), f, indent=2)
        
    print(f"\nEvent log saved to {events_file}")

if __name__ == "__main__":
    main()
