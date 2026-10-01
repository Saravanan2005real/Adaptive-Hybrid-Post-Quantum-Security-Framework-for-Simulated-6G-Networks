import copy
from typing import Dict, Optional, Any
from src.security.environment.models import (
    DeviceContext, EdgeContext, CoreContext,
    CommunicationContext, SecurityContext, SecurityMode, AuthStatus, OperationalState, EnvironmentEventType
)
from src.security.environment.telemetry import TelemetryStore

def validate_safe_metadata(data: Any):
    if isinstance(data, (str, int, float, bool)) or data is None:
        return
    if isinstance(data, list):
        for item in data:
            validate_safe_metadata(item)
        return
    if isinstance(data, dict):
        for k, v in data.items():
            if not isinstance(k, str):
                raise ValueError(f"Metadata key {k} is not a string.")
            validate_safe_metadata(v)
        return
    raise ValueError(f"Unsafe metadata type detected: {type(data)}")

class EnvironmentManager:
    def __init__(self):
        self.devices: Dict[str, DeviceContext] = {}
        self.edges: Dict[str, EdgeContext] = {}
        self.cores: Dict[str, CoreContext] = {}
        self.comm_contexts: Dict[str, CommunicationContext] = {}
        self.telemetry = TelemetryStore()
        self.current_tick = 0
        
    def update_tick(self, tick: int):
        self.current_tick = tick

    def register_device(self, ctx: DeviceContext):
        if ctx.device_id in self.devices:
            raise ValueError(f"Device {ctx.device_id} already registered.")
        if ctx.connected_edge_id and ctx.connected_edge_id not in self.edges:
            raise ValueError(f"Unknown edge {ctx.connected_edge_id}")
        self.devices[ctx.device_id] = ctx
        if ctx.connected_edge_id:
            self.edges[ctx.connected_edge_id].connected_device_ids.append(ctx.device_id)

    def register_edge(self, ctx: EdgeContext):
        if ctx.edge_id in self.edges:
            raise ValueError(f"Edge {ctx.edge_id} already registered.")
        if ctx.connected_core_id and ctx.connected_core_id not in self.cores:
            raise ValueError(f"Unknown core {ctx.connected_core_id}")
        self.edges[ctx.edge_id] = ctx
        if ctx.connected_core_id:
            self.cores[ctx.connected_core_id].connected_edge_ids.append(ctx.edge_id)

    def register_core(self, ctx: CoreContext):
        if ctx.core_id in self.cores:
            raise ValueError(f"Core {ctx.core_id} already registered.")
        self.cores[ctx.core_id] = ctx

    def entity_exists(self, entity_id: str) -> bool:
        return entity_id in self.devices or entity_id in self.edges or entity_id in self.cores
        
    def get_entity(self, entity_id: str) -> Any:
        if entity_id in self.devices:
            return self.devices[entity_id]
        if entity_id in self.edges:
            return self.edges[entity_id]
        if entity_id in self.cores:
            return self.cores[entity_id]
        return None

    def update_entity_state(self, entity_id: str, new_state: OperationalState):
        ent = self.get_entity(entity_id)
        if not ent:
            raise ValueError(f"Unknown entity {entity_id}")
            
        old_state = ent.operational_state
        ent.operational_state = new_state
        
        meta = copy.deepcopy({"old_state": old_state.value, "new_state": new_state.value})
        self.telemetry.record(
            self.current_tick, 
            EnvironmentEventType.OPERATIONAL_STATE_CHANGED.value,
            "", 
            entity_id, 
            meta
        )

    def create_communication_context(self, context_id: str, source_id: str, dest_id: str, mode: SecurityMode) -> CommunicationContext:
        if context_id in self.comm_contexts:
            raise ValueError(f"Context {context_id} already exists.")
        if source_id == dest_id:
            raise ValueError("Source and destination cannot be the same entity.")
        if not self.entity_exists(source_id) or not self.entity_exists(dest_id):
            raise ValueError("Source or destination entity does not exist.")
            
        src_ent = self.get_entity(source_id)
        dst_ent = self.get_entity(dest_id)
        
        if mode not in src_ent.supported_security_modes:
            raise ValueError(f"Mode {mode} not supported by source entity.")
        if mode not in dst_ent.supported_security_modes:
            raise ValueError(f"Mode {mode} not supported by destination entity.")
            
        # Topology validation
        if source_id in self.devices and dest_id in self.cores:
            dev = self.devices[source_id]
            if not dev.connected_edge_id or dev.connected_edge_id not in self.edges:
                raise ValueError("Device connected edge is invalid.")
            edge = self.edges[dev.connected_edge_id]
            if edge.connected_core_id != dest_id:
                raise ValueError("Device edge is not connected to destination core.")
                
        elif source_id in self.edges and dest_id in self.cores:
            edge = self.edges[source_id]
            if edge.connected_core_id != dest_id:
                raise ValueError("Edge is not connected to destination core.")
        else:
            # We reject any unknown/unsupported topology combinations for strictness
            raise ValueError("Unsupported source/destination entity relationship.")

        sec = SecurityContext(
            security_mode=mode,
            auth_status=AuthStatus.UNAUTHENTICATED,
            encryption_active=False,
            last_activity_tick=self.current_tick
        )
        ctx = CommunicationContext(
            context_id=context_id,
            source_id=source_id,
            destination_id=dest_id,
            security=sec,
            creation_tick=self.current_tick,
            last_activity_tick=self.current_tick
        )
        self.comm_contexts[context_id] = ctx
        
        meta = copy.deepcopy({"dest_id": dest_id, "mode": mode.value})
        self.telemetry.record(
            self.current_tick, 
            EnvironmentEventType.CONTEXT_CREATED.value, 
            context_id, 
            source_id, 
            meta
        )
        return ctx
        
    def _validate_auth_transition(self, old_s: AuthStatus, new_s: AuthStatus):
        if old_s == new_s:
            return
        allowed = {
            AuthStatus.UNAUTHENTICATED: [AuthStatus.AUTHENTICATING],
            AuthStatus.AUTHENTICATING: [AuthStatus.AUTHENTICATED, AuthStatus.FAILED],
            AuthStatus.AUTHENTICATED: [AuthStatus.UNAUTHENTICATED, AuthStatus.FAILED],
            AuthStatus.FAILED: [AuthStatus.AUTHENTICATING]
        }
        if new_s not in allowed[old_s]:
            raise ValueError(f"Invalid auth_status transition: {old_s.name} -> {new_s.name}")

    def update_security_context(self, context_id: str, **kwargs):
        if context_id not in self.comm_contexts:
            raise ValueError("Context not found")
            
        ctx = self.comm_contexts[context_id]
        sec = ctx.security
        
        allowed_fields = {"security_mode", "auth_status", "encryption_active", "session_id", "active_algorithms", "metadata"}
        for k in kwargs:
            if k not in allowed_fields:
                raise ValueError(f"Unknown or unsupported field: {k}")
                
        if "metadata" in kwargs:
            validate_safe_metadata(kwargs["metadata"])
            
        if "security_mode" in kwargs:
            if not isinstance(kwargs["security_mode"], SecurityMode):
                raise ValueError("security_mode must be SecurityMode")
            src_ent = self.get_entity(ctx.source_id)
            dst_ent = self.get_entity(ctx.destination_id)
            if kwargs["security_mode"] not in src_ent.supported_security_modes:
                raise ValueError(f"Mode {kwargs['security_mode']} not supported by source entity.")
            if kwargs["security_mode"] not in dst_ent.supported_security_modes:
                raise ValueError(f"Mode {kwargs['security_mode']} not supported by destination entity.")
            
        if "auth_status" in kwargs:
            if not isinstance(kwargs["auth_status"], AuthStatus):
                raise ValueError("auth_status must be AuthStatus")
            self._validate_auth_transition(sec.auth_status, kwargs["auth_status"])
            
        if "encryption_active" in kwargs and not isinstance(kwargs["encryption_active"], bool):
            raise ValueError("encryption_active must be bool")
            
        if "session_id" in kwargs and not isinstance(kwargs["session_id"], str) and kwargs["session_id"] is not None:
            raise ValueError("session_id must be str or None")
            
        if "active_algorithms" in kwargs:
            if not isinstance(kwargs["active_algorithms"], list):
                raise ValueError("active_algorithms must be list")
            for alg in kwargs["active_algorithms"]:
                if not isinstance(alg, str):
                    raise ValueError("active_algorithms elements must be strings")
            
            # Check algorithm compatibility against source/destination if they define it
            src_ent = self.get_entity(ctx.source_id)
            dst_ent = self.get_entity(ctx.destination_id)
            for ent in [src_ent, dst_ent]:
                if hasattr(ent, "supported_classical_crypto") and hasattr(ent, "supported_pqc_crypto"):
                    all_supported = ent.supported_classical_crypto + ent.supported_pqc_crypto
                    for alg in kwargs["active_algorithms"]:
                        if alg not in all_supported:
                            raise ValueError(f"Algorithm {alg} is not supported by entity {ent}")
                    
        events_to_emit = []
        
        # Simulate new state for cross-field consistency validation
        new_session_id = kwargs.get("session_id", sec.session_id)
        new_encryption_active = kwargs.get("encryption_active", sec.encryption_active)
        
        if new_session_id is None and new_encryption_active is True:
            raise ValueError("Inconsistent state: encryption_active cannot be True when session_id is None.")
        
        if "auth_status" in kwargs:
            old_s = sec.auth_status
            new_s = kwargs["auth_status"]
            if old_s == AuthStatus.UNAUTHENTICATED and new_s == AuthStatus.AUTHENTICATING:
                events_to_emit.append(EnvironmentEventType.AUTHENTICATION_STARTED)
            elif old_s == AuthStatus.AUTHENTICATING and new_s == AuthStatus.AUTHENTICATED:
                events_to_emit.append(EnvironmentEventType.AUTHENTICATION_SUCCESS)
            elif old_s == AuthStatus.AUTHENTICATING and new_s == AuthStatus.FAILED:
                events_to_emit.append(EnvironmentEventType.AUTHENTICATION_FAILED)
                
        if "security_mode" in kwargs and kwargs["security_mode"] != sec.security_mode:
            events_to_emit.append(EnvironmentEventType.SECURITY_MODE_CHANGED)
            
        if "encryption_active" in kwargs and kwargs["encryption_active"] != sec.encryption_active:
            if kwargs["encryption_active"]:
                events_to_emit.append(EnvironmentEventType.ENCRYPTION_ENABLED)
            else:
                events_to_emit.append(EnvironmentEventType.ENCRYPTION_DISABLED)
                
        if "session_id" in kwargs and kwargs["session_id"] != sec.session_id:
            if sec.session_id is None and kwargs["session_id"] is not None:
                events_to_emit.append(EnvironmentEventType.SESSION_ESTABLISHED)
            elif sec.session_id is not None and kwargs["session_id"] is None:
                events_to_emit.append(EnvironmentEventType.SESSION_TERMINATED)

        # Commit state only after all validations have passed
        for k, v in kwargs.items():
            setattr(sec, k, v)
                
        sec.last_activity_tick = self.current_tick
        ctx.last_activity_tick = self.current_tick
        
        # Determine the safe telemetry metadata to emit
        safe_kwargs = {k: v.value if hasattr(v, "value") else v for k, v in kwargs.items()}
        meta = copy.deepcopy(safe_kwargs)
        
        for ev in events_to_emit:
            self.telemetry.record(self.current_tick, ev.value, context_id, ctx.source_id, meta)
            
        if not events_to_emit:
            self.telemetry.record(self.current_tick, EnvironmentEventType.CONTEXT_UPDATED.value, context_id, ctx.source_id, meta)

    def get_snapshot(self) -> Dict[str, Any]:
        snap = {
            "tick": self.current_tick,
            "devices": {k: self._serialize_ctx(v) for k, v in self.devices.items()},
            "edges": {k: self._serialize_ctx(v) for k, v in self.edges.items()},
            "cores": {k: self._serialize_ctx(v) for k, v in self.cores.items()},
            "communication_contexts": {k: self._serialize_ctx(v) for k, v in self.comm_contexts.items()},
            "telemetry_count": len(self.telemetry.records)
        }
        validate_safe_metadata(snap)
        return snap
        
    def _serialize_ctx(self, obj: Any) -> Dict[str, Any]:
        if isinstance(obj, list):
            return [self._serialize_ctx(x) for x in obj]
        elif isinstance(obj, dict):
            return {k: self._serialize_ctx(v) for k, v in obj.items()}
        elif hasattr(obj, "__dataclass_fields__"):
            res = {}
            for k in obj.__dataclass_fields__:
                val = getattr(obj, k)
                res[k] = self._serialize_ctx(val)
            return res
        elif hasattr(obj, "value"):
            return obj.value
        else:
            return obj
