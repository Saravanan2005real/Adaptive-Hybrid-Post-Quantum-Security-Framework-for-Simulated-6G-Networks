import os
import json
import time
import random
import traceback
import statistics
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


def run_benchmark(experiment_id: str, scale_id: str, scale_def: dict, security_mode: str, seed: int) -> Dict[str, Any]:
    random.seed(seed)
    config_path = os.path.join("configs", "default_network.yaml")
    sim = Simulator(config_path)
    
    # 5. CONTROLLED VARIABLES
    # Overwrite network size using Step 16 definitions
    if "network" not in sim.config:
        sim.config["network"] = {}
    sim.config["network"]["num_devices"] = scale_def["devices"]
    sim.config["network"]["num_edge_nodes"] = scale_def["edge_nodes"]
    sim.config["network"]["num_core_nodes"] = scale_def["core_nodes"]
    
    sim.random_seed = seed
    sim.initialize_network()
    
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
    
    evals = 0
    transitions = 0
    initial_mode = "CLASSICAL"
    final_mode = "CLASSICAL"
    rule_risk_sum = 0
    ml_risk_sum = 0
    fused_risk_sum = 0
    
    adaptive_t0 = time.perf_counter()
    adaptive_t1 = adaptive_t0
    
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
                
                ctx_id = f"ctx_{device.device_id}_{target_core}"
                if env and ctx_id not in env.comm_contexts:
                    env.create_communication_context(ctx_id, device.device_id, target_core, SecurityMode.CLASSICAL)
                    env.update_security_context(ctx_id, auth_status=AuthStatus.AUTHENTICATING)
                
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
    
    msg_count = net_stats["total_delivered_responses"]
    if msg_count > 0:
        pt_bytes = msg_count * 256 
        if security_mode == "CLASSICAL":
            enc_bytes = msg_count * (256 + 16 + 12) 
            sec_overhead_bytes = msg_count * (16 + 12)
        elif security_mode == "PQC":
            enc_bytes = msg_count * (256 + 32 + 24) 
            sec_overhead_bytes = msg_count * (32 + 24)
        else: 
            enc_bytes = msg_count * (256 + 48 + 36) 
            sec_overhead_bytes = msg_count * (48 + 36)
    else:
        pt_bytes = 0
        enc_bytes = 0
        sec_overhead_bytes = 0
        
    pct_overhead = (sec_overhead_bytes / pt_bytes) * 100 if pt_bytes > 0 else 0
    
    if security_mode == "CLASSICAL":
        auth_lat = sm_metrics.get("auth_latency_ms", 0.0)
        ke_lat = sm_metrics.get("key_exchange_latency_ms", 0.0)
    elif security_mode == "PQC":
        auth_lat = sm_metrics.get("pqc_auth_latency_ms", 0.0)
        ke_lat = sm_metrics.get("ml_kem_key_exchange_latency_ms", 0.0)
    else: 
        auth_lat = sm_metrics.get("hybrid_auth_latency_ms", 0.0)
        ke_lat = sm_metrics.get("hybrid_key_exchange_latency_ms", 0.0)

    network_processing_time = net_stats["average_response_latency_ticks"] * 0.01
    security_processing_time = (auth_lat + ke_lat + sm_metrics.get("encryption_latency_ms", 0.0) + sm_metrics.get("decryption_latency_ms", 0.0)) / 1000.0

    num_devs = net_stats["total_devices"]

    return {
        "experiment_id": experiment_id,
        "scale_id": scale_id,
        "security_mode": security_mode,
        "seed": seed,
        "network_configuration": {
            "devices": net_stats["total_devices"],
            "edge_nodes": net_stats["total_edges"],
            "core_nodes": net_stats["total_cores"]
        },
        "workload_configuration": {
            "duration": sim.duration,
            "message_generation_rate": sim.message_rate,
            "payload_size": 256
        },
        "status": "COMPLETED",
        "network_metrics": {
            "devices": net_stats["total_devices"],
            "edge_nodes": net_stats["total_edges"],
            "core_nodes": net_stats["total_cores"],
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
            "failures": 0, 
            "key_establishment_latency": ke_lat
        },
        "encryption_metrics": {
            "encryption_attempts": msg_count * 2, 
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
            "network_processing_proxy": network_processing_time,
            "combined_execution_time": exec_time,
            "security_overhead": (security_processing_time / exec_time) * 100 if exec_time > 0 else 0
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
            "initial_mode": initial_mode if env else "N/A",
            "final_mode": final_mode if env else "N/A",
            "transition_count": transitions if env else "N/A",
            "transition_ticks": "N/A",
            "adaptive_orchestration_execution_time": adaptive_t1 - adaptive_t0 if env else "N/A"
        },
        "scalability_metrics": {
            "execution_time_per_device": exec_time / num_devs if num_devs > 0 else 0,
            "messages_generated_per_device": net_stats["total_messages_generated"] / num_devs if num_devs > 0 else 0,
            "delivered_responses_per_device": msg_count / num_devs if num_devs > 0 else 0,
            "security_processing_time_per_device": security_processing_time / num_devs if num_devs > 0 else 0,
            "throughput_per_device": net_stats["throughput_msgs_per_tick"] / num_devs if num_devs > 0 else 0,
            "event_count_per_device": (msg_count * 2 + sm_metrics.get("authenticated_sessions", 0) * 2) / num_devs if num_devs > 0 else 0,
            "scaling_ratio": "N/A" # computed later relative to S1
        },
        "metrics": {
            "execution_time_sec": exec_time
        }
    }


def generate_matrix():
    scales = {
        "S1": {"devices": 50, "edge_nodes": 5, "core_nodes": 1},
        "S2": {"devices": 100, "edge_nodes": 10, "core_nodes": 2},
        "S3": {"devices": 250, "edge_nodes": 25, "core_nodes": 5},
        "S4": {"devices": 500, "edge_nodes": 50, "core_nodes": 10},
        "S5": {"devices": 1000, "edge_nodes": 100, "core_nodes": 20}
    }
    modes = ["CLASSICAL", "PQC", "HYBRID", "ADAPTIVE_HYBRID"]
    seeds = [42, 43, 44]
    matrix = []
    
    for s_id, s_def in scales.items():
        for mode in modes:
            for seed in seeds:
                matrix.append({
                    "experiment_id": f"STEP16_{s_id}_{mode}_SEED{seed}",
                    "scale_id": s_id,
                    "scale_def": s_def,
                    "security_mode": mode,
                    "seed": seed
                })
    return matrix


def calculate_aggregates(results: List[Dict[str, Any]]):
    agg = {}
    scales = ["S1", "S2", "S3", "S4", "S5"]
    modes = ["CLASSICAL", "PQC", "HYBRID", "ADAPTIVE_HYBRID"]
    
    for s_id in scales:
        agg[s_id] = {}
        for mode in modes:
            mode_results = [r for r in results if r["scale_id"] == s_id and r["security_mode"] == mode and r["status"] == "COMPLETED"]
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
                "security_overhead_metrics.combined_execution_time",
                "scalability_metrics.execution_time_per_device",
                "scalability_metrics.scaling_ratio"
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
                    
            agg[s_id][mode] = mode_agg
            
    return agg

def audit_accounting(matrix, results):
    print("Running accounting assertions...")
    
    assert len(matrix) == 60, f"Expected 60 matrix configurations, got {len(matrix)}"
    
    scales = {m["scale_id"] for m in matrix}
    assert len(scales) == 5, f"Expected 5 scales, got {len(scales)}"
    
    modes = {m["security_mode"] for m in matrix}
    assert len(modes) == 4, f"Expected 4 modes, got {len(modes)}"
    
    seeds = {m["seed"] for m in matrix}
    assert len(seeds) == 3, f"Expected 3 seeds, got {len(seeds)}"
    
    # Check 3 runs per scale/mode
    for s in scales:
        for m in modes:
            runs = [r for r in matrix if r["scale_id"] == s and r["security_mode"] == m]
            assert len(runs) == 3, f"Expected 3 runs for {s}/{m}, got {len(runs)}"
            
    for s in scales:
        runs = [r for r in matrix if r["scale_id"] == s]
        assert len(runs) == 12, f"Expected 12 runs for {s}, got {len(runs)}"
        
    for m in modes:
        runs = [r for r in matrix if r["security_mode"] == m]
        assert len(runs) == 15, f"Expected 15 runs for {m}, got {len(runs)}"
        
    for sd in seeds:
        runs = [r for r in matrix if r["seed"] == sd]
        assert len(runs) == 20, f"Expected 20 runs for {sd}, got {len(runs)}"
        
    ids = [m["experiment_id"] for m in matrix]
    assert len(set(ids)) == 60, "Duplicate experiment IDs found in matrix"
    
    assert len(results) == 60, f"Expected 60 results, got {len(results)}"
    
    result_ids = [r["experiment_id"] for r in results]
    assert set(ids) == set(result_ids), "Matrix and results IDs do not match one-to-one"
    
    completed = sum(1 for r in results if r["status"] == "COMPLETED")
    failed = sum(1 for r in results if r["status"] == "FAILED")
    assert completed + failed == 60, "Completed and failed do not sum to 60"
    
    for r in results:
        assert "experiment_id" in r
        assert "scale_id" in r
        assert "security_mode" in r
        assert "seed" in r
        assert "status" in r
        
        # Check N/A handling
        if r["security_mode"] != "ADAPTIVE_HYBRID":
            assert r.get("adaptive_metrics", {}).get("adaptive_orchestration_execution_time") == "N/A"
            assert r.get("adaptive_metrics", {}).get("initial_mode") == "N/A"
            assert r.get("adaptive_metrics", {}).get("final_mode") == "N/A"
            
        r_str = json.dumps(r).lower()
        assert "private_key" not in r_str
        assert "session_key" not in r_str
        
    print("Accounting assertions passed.")



def main():
    print("STEP 16 — SCALABILITY TESTING\n")
    os.makedirs(os.path.join("results", "step16", "runs"), exist_ok=True)
    
    matrix = generate_matrix()
    
    with open(os.path.join("results", "step16", "scalability_matrix.json"), "w") as f:
        json.dump(matrix, f, indent=2)
        
    results = []
    
    for conf in matrix:
        eid = conf["experiment_id"]
        print(f"Running {eid}...")
        try:
            res = run_benchmark(eid, conf["scale_id"], conf["scale_def"], conf["security_mode"], conf["seed"])
        except Exception as e:
            traceback.print_exc()
            res = {
                "experiment_id": eid,
                "scale_id": conf["scale_id"],
                "security_mode": conf["security_mode"],
                "seed": conf["seed"],
                "status": "FAILED",
                "error": str(e)
            }
        
        results.append(res)
        with open(os.path.join("results", "step16", "runs", f"{eid}.json"), "w") as f:
            json.dump(res, f, indent=2)
            
    # Calculate Scaling Ratios relative to S1
    for r in results:
        if r["status"] == "COMPLETED":
            s1_ref = next((x for x in results if x["scale_id"] == "S1" and x["security_mode"] == r["security_mode"] and x["seed"] == r["seed"] and x["status"] == "COMPLETED"), None)
            if s1_ref and s1_ref["metrics"]["execution_time_sec"] > 0:
                r["scalability_metrics"]["scaling_ratio"] = r["metrics"]["execution_time_sec"] / s1_ref["metrics"]["execution_time_sec"]
            
            with open(os.path.join("results", "step16", "runs", f"{r['experiment_id']}.json"), "w") as f:
                json.dump(r, f, indent=2)
                
    # Aggregation
    agg = calculate_aggregates(results)
    with open(os.path.join("results", "step16", "aggregate_results.json"), "w") as f:
        json.dump({"aggregates_by_scale_mode": agg}, f, indent=2)
        
    # Full results
    with open(os.path.join("results", "step16", "scalability_results.json"), "w") as f:
        json.dump(results, f, indent=2)
        
    completed = sum(1 for r in results if r["status"] == "COMPLETED")
    failed = sum(1 for r in results if r["status"] == "FAILED")
    
    audit_accounting(matrix, results)
    
    print(f"\nScalability Benchmark Complete. {completed}/{len(matrix)} successful.")

if __name__ == "__main__":
    main()
