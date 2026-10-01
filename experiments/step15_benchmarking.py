import os
import json
import time
import random
import traceback
import statistics
import copy
from typing import Dict, Any, List

from src.simulator import Simulator
from src.events import EventLogger, EventType
from src.security.manager import SecurityManager, ProtectedMessagePayload
from src.security.pqc.manager import PQCSecurityManager
from src.security.hybrid.manager import HybridSecurityManager
from src.security.environment.manager import EnvironmentManager
from src.security.environment.models import (
    DeviceContext, EdgeContext, CoreContext, SecurityMode, AuthStatus, OperationalState, EnvironmentEventType
)
from src.security.risk.manager import RiskManager
from src.security.ml_risk.predictor import MLRiskPredictorAPI
from src.security.adaptive.engine import AdaptiveSecurityEngine


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


def run_benchmark(experiment_id: str, security_mode: str, seed: int) -> Dict[str, Any]:
    random.seed(seed)
    config_path = os.path.join("configs", "default_network.yaml")
    sim = Simulator(config_path)
    sim.random_seed = seed
    sim.initialize_network()
    
    # 50 ticks is default, let's keep it
    
    logger = EventLogger()
    
    # Setup Managers based on mode
    if security_mode == "CLASSICAL":
        sec_manager = SecurityManager(logger)
    elif security_mode == "PQC":
        sec_manager = PQCSecurityManager(logger)
    elif security_mode in ["HYBRID", "ADAPTIVE_HYBRID"]:
        sec_manager = HybridSecurityManager(logger)
    else:
        raise ValueError(f"Unknown mode {security_mode}")

    # Register all devices and cores with crypto manager
    for dev_id in sim.network.devices:
        sec_manager.register_device(dev_id)
    for core_id in sim.network.cores:
        sec_manager.register_device(core_id)
        
    for dev_id, device in sim.network.devices.items():
        sim.network.devices[dev_id] = SecureDeviceWrapper(device, sec_manager)
    for core_id, core in sim.network.cores.items():
        sim.network.cores[core_id] = SecureCoreWrapper(core, sec_manager)
        
    # Adaptive Setup if applicable
    adaptive_engine = None
    env = None
    if security_mode == "ADAPTIVE_HYBRID":
        env = EnvironmentManager()
        model_path = "results/ml_risk_model.pkl"
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"ML model not found at {model_path}.")
        ml_api = MLRiskPredictorAPI(model_path)
        risk = RiskManager(env, logger)
        adaptive_engine = AdaptiveSecurityEngine(env, risk, ml_api, logger)
        
        for core_id in sim.network.cores:
            env.register_core(CoreContext(core_id, OperationalState.ONLINE, [SecurityMode.CLASSICAL, SecurityMode.PQC, SecurityMode.HYBRID]))
        for edge_id, edge in sim.network.edges.items():
            env.register_edge(EdgeContext(edge_id, OperationalState.ONLINE, [SecurityMode.CLASSICAL, SecurityMode.PQC, SecurityMode.HYBRID], edge.connected_core_id))
        for dev_id, dev in sim.network.devices.items():
            env.register_device(DeviceContext(dev_id, "ue", OperationalState.ONLINE, [SecurityMode.CLASSICAL, SecurityMode.PQC, SecurityMode.HYBRID], ["ed25519"], ["mldsa"], dev.connected_edge_id))
            
    start_time = time.time()
    
    # Pre-populate adaptive tracking stats
    evals = 0
    transitions = 0
    initial_mode = "CLASSICAL"
    final_mode = "CLASSICAL"
    rule_risk_sum = 0
    ml_risk_sum = 0
    fused_risk_sum = 0
    
    adaptive_t0 = time.perf_counter()
    adaptive_t1 = adaptive_t0
    
    # Run the simulation loops
    for tick in range(1, sim.duration + 1):
        sim.current_tick = tick
        if env:
            env.update_tick(tick)
            
        core_ids = list(sim.network.cores.keys())
        for device in sim.network.devices.values():
            if random.random() < sim.message_rate:
                edge = sim.network.edges.get(device.connected_edge_id)
                if not edge or not edge.connected_core_id:
                    continue
                target_core = edge.connected_core_id
                
                # ADAPTIVE: create context if needed
                ctx_id = f"ctx_{device.device_id}_{target_core}"
                if env and ctx_id not in env.comm_contexts:
                    env.create_communication_context(ctx_id, device.device_id, target_core, SecurityMode.CLASSICAL)
                    env.update_security_context(ctx_id, auth_status=AuthStatus.AUTHENTICATING)
                
                # Auth if needed
                if (device.device_id, target_core) not in sec_manager.sessions:
                    success = sec_manager.authenticate_and_exchange(device.device_id, target_core, timestamp=tick)
                    if not success:
                        if env:
                            env.telemetry.record(tick, EnvironmentEventType.AUTHENTICATION_FAILED.value, ctx_id, device.device_id, {})
                        continue
                    if env:
                        env.update_security_context(ctx_id, auth_status=AuthStatus.AUTHENTICATED, encryption_active=True, session_id=f"ses_{tick}")
                
                msg = device.generate_message(
                    target_core_id=target_core,
                    payload={"data": "sensor_reading", "val": random.random()},
                    size=256,
                    timestamp=tick
                )
                if msg:
                    sim.logger.log(EventType.MESSAGE_CREATED, tick, message_id=msg.message_id, device_id=device.device_id, target_core_id=target_core)
                    sim.total_messages_generated += 1
                    
                if env:
                    res = adaptive_engine.evaluate(ctx_id)
                    evals += 1
                    rule_risk_sum += res.rule_risk_score
                    ml_risk_sum += res.ml_risk_score
                    fused_risk_sum += res.fused_risk_score
                    if res.transition_applied:
                        transitions += 1
                        final_mode = res.recommended_security_mode.name
        
        sim.network.step(tick)
        
    if env:
        adaptive_t1 = time.perf_counter()
    
    end_time = time.time()
    exec_time = end_time - start_time
    
    net_stats = sim.get_summary()
    sm_metrics = sec_manager.metrics
    
    # Calculate bytes (approximated based on AERIS architecture representations)
    msg_count = net_stats["total_delivered_responses"]
    if msg_count > 0:
        # Standard payloads
        pt_bytes = msg_count * 256 # baseline payload
        if security_mode == "CLASSICAL":
            enc_bytes = msg_count * (256 + 16 + 12) # AES-GCM tag + nonce
            sec_overhead_bytes = msg_count * (16 + 12)
        elif security_mode == "PQC":
            enc_bytes = msg_count * (256 + 32 + 24) # larger nonces/tags in pqc placeholders
            sec_overhead_bytes = msg_count * (32 + 24)
        else: # HYBRID
            enc_bytes = msg_count * (256 + 48 + 36) # combined bounds
            sec_overhead_bytes = msg_count * (48 + 36)
    else:
        pt_bytes = 0
        enc_bytes = 0
        sec_overhead_bytes = 0
        
    pct_overhead = (sec_overhead_bytes / pt_bytes) * 100 if pt_bytes > 0 else 0
    
    # Key establishment latency fields differ by manager, standardize them:
    if security_mode == "CLASSICAL":
        auth_lat = sm_metrics.get("auth_latency_ms", 0.0)
        ke_lat = sm_metrics.get("key_exchange_latency_ms", 0.0)
    elif security_mode == "PQC":
        auth_lat = sm_metrics.get("pqc_auth_latency_ms", 0.0)
        ke_lat = sm_metrics.get("ml_kem_key_exchange_latency_ms", 0.0)
    else: # HYBRID or ADAPTIVE_HYBRID
        auth_lat = sm_metrics.get("hybrid_auth_latency_ms", 0.0)
        ke_lat = sm_metrics.get("hybrid_key_exchange_latency_ms", 0.0)

    # Calculate standard execution times
    network_processing_time = net_stats["average_response_latency_ticks"] * 0.01  # proxy metric
    security_processing_time = (auth_lat + ke_lat + sm_metrics.get("encryption_latency_ms", 0.0) + sm_metrics.get("decryption_latency_ms", 0.0)) / 1000.0

    return {
        "experiment_id": experiment_id,
        "security_mode": security_mode,
        "seed": seed,
        "configuration": {
            "network": "default_network.yaml",
            "duration": sim.duration,
            "devices": net_stats["total_devices"],
            "edges": net_stats["total_edges"],
            "cores": net_stats["total_cores"]
        },
        "status": "COMPLETED",
        "network_metrics": {
            "messages_generated": net_stats["total_messages_generated"],
            "responses_delivered": net_stats["total_delivered_responses"],
            "failed_messages": net_stats["total_failed_messages"],
            "in_flight_messages": net_stats.get("in_flight_messages", 0),
            "average_response_latency": net_stats["average_response_latency_ticks"],
            "throughput": net_stats["throughput_msgs_per_tick"]
        },
        "authentication_metrics": {
            "authentication_attempts": sm_metrics.get("authenticated_sessions", 0) + sm_metrics.get("auth_failures", 0),
            "successful_authentications": sm_metrics.get("authenticated_sessions", 0),
            "authentication_failures": sm_metrics.get("auth_failures", 0),
            "authentication_latency": auth_lat
        },
        "key_establishment_metrics": {
            "key_establishment_attempts": sm_metrics.get("authenticated_sessions", 0),
            "successful_exchanges": sm_metrics.get("authenticated_sessions", 0),
            "failed_exchanges": 0, # AERIS assumes auth success implies key exchange success for baseline
            "key_establishment_latency": ke_lat
        },
        "encryption_metrics": {
            "encryption_attempts": msg_count * 2, # req + resp
            "encryption_failures": sm_metrics.get("encryption_failures", 0),
            "encryption_latency": sm_metrics.get("encryption_latency_ms", 0.0)
        },
        "decryption_metrics": {
            "decryption_attempts": msg_count * 2,
            "decryption_failures": sm_metrics.get("decryption_failures", 0),
            "decryption_latency": sm_metrics.get("decryption_latency_ms", 0.0)
        },
        "security_overhead_metrics": {
            "security_processing_time": security_processing_time,
            "network_processing_time": network_processing_time,
            "combined_execution_time": exec_time,
            "security_overhead": (security_processing_time / exec_time) * 100 if exec_time > 0 else 0
        },
        "resource_metrics": {
            "cpu_time": "N/A", # OS-dependent, not uniformly measurable in synthetic wrapper
            "process_cpu_usage": "N/A",
            "peak_memory_usage": "N/A",
            "memory_delta": "N/A"
        },
        "communication_overhead_metrics": {
            "plaintext_payload_bytes": pt_bytes,
            "protected_message_bytes": enc_bytes,
            "security_overhead_bytes": sec_overhead_bytes,
            "overhead_percentage": pct_overhead
        },
        "adaptive_metrics": {
            "rule_risk": rule_risk_sum / evals if evals > 0 else "N/A",
            "ml_risk": ml_risk_sum / evals if evals > 0 else "N/A",
            "fused_risk": fused_risk_sum / evals if evals > 0 else "N/A",
            "initial_security_mode": initial_mode if env else "N/A",
            "final_security_mode": final_mode if env else "N/A",
            "transition_count": transitions if env else "N/A",
            "transition_ticks": "N/A", # Only applicable if attack triggered
            "hysteresis_behavior": "N/A",
            "cooldown_behavior": "N/A",
            "adaptive_orchestration_execution_time": adaptive_t1 - adaptive_t0 if env else "N/A"
        },
        "metrics": {
            "execution_time_sec": exec_time
        }
    }


def generate_matrix():
    modes = ["CLASSICAL", "PQC", "HYBRID", "ADAPTIVE_HYBRID"]
    seeds = [42, 43, 44, 45, 46]
    matrix = []
    for mode in modes:
        for seed in seeds:
            matrix.append({
                "experiment_id": f"STEP15_{mode}_SEED{seed}",
                "security_mode": mode,
                "seed": seed
            })
    return matrix


def calculate_aggregates(results: List[Dict[str, Any]]):
    agg = {}
    modes = ["CLASSICAL", "PQC", "HYBRID", "ADAPTIVE_HYBRID"]
    
    for mode in modes:
        mode_results = [r for r in results if r["security_mode"] == mode and r["status"] == "COMPLETED"]
        if not mode_results:
            continue
            
        def extract(metric_path):
            vals = []
            for r in mode_results:
                parts = metric_path.split(".")
                curr = r
                for p in parts:
                    curr = curr[p]
                if curr != "N/A":
                    vals.append(curr)
            return vals
            
        metrics_to_agg = [
            "network_metrics.messages_generated",
            "network_metrics.responses_delivered",
            "network_metrics.average_response_latency",
            "network_metrics.throughput",
            "authentication_metrics.authentication_latency",
            "key_establishment_metrics.key_establishment_latency",
            "encryption_metrics.encryption_latency",
            "decryption_metrics.decryption_latency",
            "communication_overhead_metrics.overhead_percentage",
            "metrics.execution_time_sec"
        ]
        
        mode_agg = {"count": len(mode_results)}
        
        for m in metrics_to_agg:
            vals = extract(m)
            if vals:
                mode_agg[m] = {
                    "mean": statistics.mean(vals),
                    "median": statistics.median(vals),
                    "min": min(vals),
                    "max": max(vals),
                    "stdev": statistics.stdev(vals) if len(vals) > 1 else 0.0
                }
            else:
                mode_agg[m] = "N/A"
                
        # Adaptive specific
        if mode == "ADAPTIVE_HYBRID":
            adap_vals = extract("adaptive_metrics.adaptive_orchestration_execution_time")
            if adap_vals:
                mode_agg["adaptive_orchestration_time"] = {
                    "mean": statistics.mean(adap_vals),
                    "min": min(adap_vals),
                    "max": max(adap_vals)
                }
                
        agg[mode] = mode_agg
        
    return agg


def main():
    print("STEP 15 — COMPREHENSIVE BENCHMARKING\n")
    os.makedirs(os.path.join("results", "step15", "runs"), exist_ok=True)
    
    matrix = generate_matrix()
    
    with open(os.path.join("results", "step15", "benchmark_matrix.json"), "w") as f:
        json.dump(matrix, f, indent=2)
        
    results = []
    
    for conf in matrix:
        eid = conf["experiment_id"]
        print(f"Running {eid}...")
        try:
            res = run_benchmark(eid, conf["security_mode"], conf["seed"])
        except Exception as e:
            traceback.print_exc()
            res = {
                "experiment_id": eid,
                "security_mode": conf["security_mode"],
                "seed": conf["seed"],
                "status": "FAILED",
                "error": str(e)
            }
        
        results.append(res)
        with open(os.path.join("results", "step15", "runs", f"{eid}.json"), "w") as f:
            json.dump(res, f, indent=2)
            
    # Aggregation
    agg = calculate_aggregates(results)
    with open(os.path.join("results", "step15", "aggregate_results.json"), "w") as f:
        json.dump({"aggregates_by_mode": agg}, f, indent=2)
        
    # Full results
    with open(os.path.join("results", "step15", "benchmark_results.json"), "w") as f:
        json.dump(results, f, indent=2)
        
    completed = sum(1 for r in results if r["status"] == "COMPLETED")
    failed = sum(1 for r in results if r["status"] == "FAILED")
    
    print(f"\nBenchmarking Complete. {completed}/{len(matrix)} successful.")

if __name__ == "__main__":
    main()
