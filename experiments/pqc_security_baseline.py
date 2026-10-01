import os
import json
import time
import random
from src.simulator import Simulator
from src.security.manager import ProtectedMessagePayload
from src.security.pqc.manager import PQCSecurityManager
from src.events import EventType

class SecureDeviceWrapper:
    def __init__(self, device, sec_manager):
        self._device = device
        self._sec = sec_manager

    def __getattr__(self, name):
        return getattr(self._device, name)

    def generate_message(self, target_core_id, payload, size, timestamp):
        try:
            protected = self._sec.encrypt_message(self.device_id, target_core_id, payload, timestamp)
            secure_payload = {"secure_payload": protected.to_dict()}
        except Exception as e:
            self._sec.logger.log(EventType.MESSAGE_FAILED, timestamp, reason=str(e), source_id=self.device_id, dest_id=target_core_id)
            return None
        return self._device.generate_message(target_core_id, secure_payload, size, timestamp)

    def receive_response(self, msg, timestamp):
        if "secure_payload" in msg.payload:
            try:
                protected_in = ProtectedMessagePayload.from_dict(msg.payload["secure_payload"])
                self._sec.decrypt_message(msg.source_id, self.device_id, protected_in, timestamp)
            except Exception as e:
                self._sec.logger.log(EventType.MESSAGE_FAILED, timestamp, reason=str(e), message_id=msg.message_id)
                return
        self._device.receive_response(msg, timestamp)


class SecureCoreWrapper:
    def __init__(self, core, sec_manager):
        self._core = core
        self._sec = sec_manager

    def __getattr__(self, name):
        return getattr(self._core, name)

    def generate_response(self, msg, timestamp):
        if "secure_payload" in msg.payload:
            try:
                protected_in = ProtectedMessagePayload.from_dict(msg.payload["secure_payload"])
                self._sec.decrypt_message(msg.source_id, self.core_id, protected_in, timestamp)
            except Exception as e:
                self._sec.logger.log(EventType.MESSAGE_FAILED, timestamp, reason=str(e), message_id=msg.message_id)
                return None
        
        try:
            protected_out = self._sec.encrypt_message(self.core_id, msg.source_id, {"ack": True, "status": "ok"}, timestamp)
        except Exception as e:
            self._sec.logger.log(EventType.MESSAGE_FAILED, timestamp, reason=str(e), message_id=msg.message_id)
            return None
            
        resp_msg = self._core.generate_response(msg, timestamp)
        if resp_msg:
            resp_msg.payload = {"secure_payload": protected_out.to_dict()}
        return resp_msg


def main():
    print("Starting AERIS-PQ6G PQC Security Baseline Simulation...")
    config_path = os.path.join("configs", "default_network.yaml")
    
    start_time = time.time()
    
    sim = Simulator(config_path)
    sim.initialize_network()
    
    sec_manager = PQCSecurityManager(sim.logger)
    
    # Register all devices and cores
    for dev_id in sim.network.devices:
        sec_manager.register_device(dev_id)
    for core_id in sim.network.cores:
        sec_manager.register_device(core_id)
        
    # Wrap network nodes without monkey-patching
    for dev_id, device in sim.network.devices.items():
        sim.network.devices[dev_id] = SecureDeviceWrapper(device, sec_manager)
        
    for core_id, core in sim.network.cores.items():
        sim.network.cores[core_id] = SecureCoreWrapper(core, sec_manager)

    # Run the simulation loops
    for tick in range(1, sim.duration + 1):
        sim.current_tick = tick
        core_ids = list(sim.network.cores.keys())
        for device in sim.network.devices.values():
            if random.random() < sim.message_rate:
                edge = sim.network.edges.get(device.connected_edge_id)
                if not edge or not edge.connected_core_id:
                    continue
                target_core = edge.connected_core_id
                
                if (device.device_id, target_core) not in sec_manager.sessions:
                    success = sec_manager.authenticate_and_exchange(device.device_id, target_core, timestamp=tick)
                    if not success:
                        continue
                    
                msg = device.generate_message(
                    target_core_id=target_core,
                    payload={"data": "sensor_reading", "val": random.random()},
                    size=256,
                    timestamp=tick
                )
                if msg:
                    sim.logger.log(EventType.MESSAGE_CREATED, tick, message_id=msg.message_id, device_id=device.device_id, target_core_id=target_core)
                    sim.total_messages_generated += 1
        
        sim.network.step(tick)
    
    end_time = time.time()
    exec_time = end_time - start_time
    
    stats = sim.get_summary()
    
    print("\n--- Security Simulation Summary ---")
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
    
    print("\n--- Security Metrics ---")
    print(f"Authenticated Sessions: {sec_manager.metrics['authenticated_sessions']}")
    print(f"Authentication Failures: {sec_manager.metrics['auth_failures']}")
    print(f"Encryption Failures: {sec_manager.metrics['encryption_failures']}")
    print(f"Decryption Failures: {sec_manager.metrics['decryption_failures']}")
    print(f"Replays Detected: {sec_manager.metrics['replays_detected']}")
    print(f"Total Auth Latency (ms): {sec_manager.metrics['pqc_auth_latency_ms']:.4f}")
    print(f"Total Key Exch Latency (ms): {sec_manager.metrics['ml_kem_key_exchange_latency_ms']:.4f}")
    print(f"Total Encrypt Latency (ms): {sec_manager.metrics['encryption_latency_ms']:.4f}")
    print(f"Total Decrypt Latency (ms): {sec_manager.metrics['decryption_latency_ms']:.4f}")

    results_dir = "results"
    os.makedirs(results_dir, exist_ok=True)
    events_file = os.path.join(results_dir, "pqc_security_events.json")
    
    with open(events_file, "w") as f:
        json.dump(sim.logger.get_events(), f, indent=2)
        
    print(f"\nEvent log saved to {events_file}")

if __name__ == "__main__":
    main()
