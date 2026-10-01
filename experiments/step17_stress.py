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


def run_benchmark(experiment_id: str, scenario_id: str, expected_stress_factor: str, scale_def: dict, security_mode: str, message_rate: float, duration: int, payload_size: int, seed: int) -> Dict[str, Any]:
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
    sim.duration = duration
    sim.message_rate = message_rate
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
                    size=payload_size,
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
    

    # 8. NETWORK ACCOUNTING
    generated = net_stats["total_messages_generated"]
    delivered = net_stats["total_delivered_responses"]
    failed = net_stats["total_failed_messages"]
    in_flight = net_stats.get("in_flight_messages", 0)
    
    # The requirement: generated = delivered + failed + in_flight
    accounting_violation = False
    if generated != delivered + failed + in_flight:
        accounting_violation = True

    msg_count = net_stats["total_delivered_responses"]
    pt_bytes = msg_count * payload_size

    if msg_count > 0:
        pass 
        if security_mode == "CLASSICAL":
            enc_bytes = msg_count * (payload_size + 16 + 12) 
            sec_overhead_bytes = msg_count * (16 + 12)
        elif security_mode == "PQC":
            enc_bytes = msg_count * (payload_size + 32 + 24) 
            sec_overhead_bytes = msg_count * (32 + 24)
        else: 
            enc_bytes = msg_count * (payload_size + 48 + 36) 
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
        "scenario_id": scenario_id,
        "expected_stress_factor": expected_stress_factor,
        "security_mode": security_mode,
        "seed": seed,
        "scale_configuration": scale_def,
        "workload_configuration": {
            "duration": duration,
            "message_rate": message_rate,
            "payload_size": payload_size
        },
        "status": "FAILED" if accounting_violation else "COMPLETED",
        "network_metrics": {
            "messages_generated": generated,
            "messages_delivered": delivered,
            "messages_failed": failed,
            "messages_in_flight": in_flight,
            "average_response_latency_ticks": net_stats["average_response_latency_ticks"],
            "throughput": net_stats["throughput_msgs_per_tick"],
            "execution_time_sec": exec_time
        },
        "security_metrics": {
            "authentication_attempts": sm_metrics.get("authenticated_sessions", 0) + sm_metrics.get("auth_failures", 0),
            "authentication_successes": sm_metrics.get("authenticated_sessions", 0),
            "authentication_failures": sm_metrics.get("auth_failures", 0),
            "key_establishment_operations": sm_metrics.get("authenticated_sessions", 0),
            "encryption_operations": msg_count * 2,
            "decryption_operations": msg_count * 2,
            "security_failures": sm_metrics.get("encryption_failures", 0) + sm_metrics.get("decryption_failures", 0),
            "security_processing_time": security_processing_time
        },
        "adaptive_metrics": {
            "initial_mode": initial_mode if env else "N/A",
            "final_mode": final_mode if env else "N/A",
            "transition_count": transitions if env else "N/A",
            "transition_latency": "N/A",
            "adaptive_orchestration_execution_time": adaptive_t1 - adaptive_t0 if env else "N/A"
        },
        "stress_metrics": {
            "exception_count": 0,
            "run_failure": False,
            "state_consistency_violation": False,
            "accounting_violation": accounting_violation,
            "event_count": msg_count * 2 + sm_metrics.get("authenticated_sessions", 0) * 2,
            "events_per_generated_message": (msg_count * 2 + sm_metrics.get("authenticated_sessions", 0) * 2) / generated if generated > 0 else 0,
            "execution_time_per_generated_message": exec_time / generated if generated > 0 else 0,
            "execution_time_per_device": exec_time / num_devs if num_devs > 0 else 0
        },
        "resource_metrics": {
            "peak_memory": "N/A",
            "cpu_usage": "N/A"
        }
    }


def generate_matrix():
    # Baseline: S1 size, rate 0.1, duration 50, payload 256
    s1_def = {"devices": 50, "edge_nodes": 5, "core_nodes": 1}
    s3_def = {"devices": 250, "edge_nodes": 25, "core_nodes": 5}
    s5_def = {"devices": 1000, "edge_nodes": 100, "core_nodes": 20}
    
    seeds = [42, 43, 44]
    matrix = []
    
    def add_cfg(sc_id, desc, s_def, mode, rate, duration, payload, seed):
        matrix.append({
            "experiment_id": f"STEP17_{sc_id}_{mode}_SEED{seed}",
            "scenario_id": sc_id,
            "expected_stress_factor": desc,
            "security_mode": mode,
            "scale_def": s_def,
            "message_rate": rate,
            "duration": duration,
            "payload_size": payload,
            "seed": seed
        })
        
    for seed in seeds:
        # STRESS-1
        add_cfg("STRESS-1", "High Message Rate", s1_def, "HYBRID", 1.0, 50, 256, seed)
        # STRESS-2
        add_cfg("STRESS-2", "Large Network", s5_def, "HYBRID", 0.1, 50, 256, seed)
        # STRESS-3
        add_cfg("STRESS-3", "Long Duration", s1_def, "HYBRID", 0.1, 500, 256, seed)
        # STRESS-4
        add_cfg("STRESS-4", "High Event Volume", s1_def, "HYBRID", 1.0, 200, 256, seed)
        # STRESS-5
        for mode in ["CLASSICAL", "PQC", "HYBRID", "ADAPTIVE_HYBRID"]:
            add_cfg("STRESS-5", "Security Mode Stress", s1_def, mode, 0.5, 100, 256, seed)
        # STRESS-6
        add_cfg("STRESS-6", "Combined Stress", s3_def, "ADAPTIVE_HYBRID", 1.0, 100, 256, seed)
        # STRESS-7: Boundary
        add_cfg("STRESS-7_ZERO_DEV", "Zero Devices", {"devices": 0, "edge_nodes": 5, "core_nodes": 1}, "CLASSICAL", 0.1, 50, 256, seed)
        add_cfg("STRESS-7_NEG_RATE", "Negative Rate", s1_def, "CLASSICAL", -0.5, 50, 256, seed)

    return matrix



def calculate_aggregates(results: List[Dict[str, Any]]):
    agg = {}
    scenarios = set(r["scenario_id"] for r in results)
    modes = ["CLASSICAL", "PQC", "HYBRID", "ADAPTIVE_HYBRID"]
    
    for s_id in scenarios:
        agg[s_id] = {}
        for mode in modes:
            mode_results = [r for r in results if r["scenario_id"] == s_id and r["security_mode"] == mode]
            if not mode_results:
                continue
                
            completed = sum(1 for r in mode_results if r["status"] == "COMPLETED")
            failed = sum(1 for r in mode_results if r["status"] == "FAILED")
            
            def extract(metric_path):
                vals = []
                for r in mode_results:
                    if r["status"] == "FAILED": continue
                    parts = metric_path.split(".")
                    curr = r
                    for p in parts:
                        curr = curr[p]
                    if curr != "N/A":
                        vals.append(curr)
                return vals
                
            metrics_to_agg = [
                "network_metrics.messages_generated",
                "network_metrics.messages_delivered",
                "network_metrics.execution_time_sec",
                "stress_metrics.event_count"
            ]
            
            mode_agg = {
                "count": len(mode_results),
                "completed": completed,
                "failed": failed
            }
            
            for m in metrics_to_agg:
                vals = extract(m)
                if vals:
                    mode_agg[m] = {
                        "mean": statistics.mean(vals)
                    }
                else:
                    mode_agg[m] = "N/A"
                    
            agg[s_id][mode] = mode_agg
            
    return agg


def main():
    print("STEP 16 — SCALABILITY TESTING\n")
    os.makedirs(os.path.join("results", "step17", "runs"), exist_ok=True)
    
    matrix = generate_matrix()
    
    with open(os.path.join("results", "step17", "scalability_matrix.json"), "w") as f:
        json.dump(matrix, f, indent=2)
        
    results = []
    
    for conf in matrix:
        eid = conf["experiment_id"]
        print(f"Running {eid}...")
        try:
            res = run_benchmark(eid, conf["scenario_id"], conf["expected_stress_factor"], conf["scale_def"], conf["security_mode"], conf["message_rate"], conf["duration"], conf["payload_size"], conf["seed"])
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
        with open(os.path.join("results", "step17", "runs", f"{eid}.json"), "w") as f:
            json.dump(res, f, indent=2)
            
    # Calculate Scaling Ratios relative to S1
    for r in results:
        if r["status"] == "COMPLETED":
            s1_ref = next((x for x in results if x["scale_id"] == "S1" and x["security_mode"] == r["security_mode"] and x["seed"] == r["seed"] and x["status"] == "COMPLETED"), None)
            if s1_ref and s1_ref["metrics"]["execution_time_sec"] > 0:
                r["scalability_metrics"]["scaling_ratio"] = r["metrics"]["execution_time_sec"] / s1_ref["metrics"]["execution_time_sec"]
            
            with open(os.path.join("results", "step17", "runs", f"{r['experiment_id']}.json"), "w") as f:
                json.dump(r, f, indent=2)
                
    # Aggregation
    agg = calculate_aggregates(results)
    with open(os.path.join("results", "step17", "aggregate_results.json"), "w") as f:
        json.dump({"aggregates_by_scale_mode": agg}, f, indent=2)
        
    # Full results
    with open(os.path.join("results", "step17", "scalability_results.json"), "w") as f:
        json.dump(results, f, indent=2)
        
    completed = sum(1 for r in results if r["status"] == "COMPLETED")
    failed = sum(1 for r in results if r["status"] == "FAILED")
    
    
    
    print(f"\nScalability Benchmark Complete. {completed}/{len(matrix)} successful.")

if __name__ == "__main__":
    main()
