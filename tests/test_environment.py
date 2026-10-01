import pytest
import json
import copy
from src.security.environment.models import (
    DeviceContext, EdgeContext, CoreContext, SecurityMode, AuthStatus, OperationalState, EnvironmentEventType
)
from src.security.environment.manager import EnvironmentManager, validate_safe_metadata

def setup_manager():
    return EnvironmentManager()

def test_register_core():
    mgr = setup_manager()
    c = CoreContext("core_1", OperationalState.ONLINE, [SecurityMode.CLASSICAL])
    mgr.register_core(c)
    assert "core_1" in mgr.cores

def test_register_edge():
    mgr = setup_manager()
    mgr.register_core(CoreContext("core_1", OperationalState.ONLINE, []))
    e = EdgeContext("edge_1", OperationalState.ONLINE, [], "core_1")
    mgr.register_edge(e)
    assert "edge_1" in mgr.edges

def test_register_device():
    mgr = setup_manager()
    mgr.register_core(CoreContext("core_1", OperationalState.ONLINE, []))
    mgr.register_edge(EdgeContext("edge_1", OperationalState.ONLINE, [], "core_1"))
    d = DeviceContext("dev_1", "iot", OperationalState.ONLINE, [], [], [], "edge_1")
    mgr.register_device(d)
    assert "dev_1" in mgr.devices

def test_duplicate_registration_rejected():
    mgr = setup_manager()
    mgr.register_core(CoreContext("core_1", OperationalState.ONLINE, []))
    with pytest.raises(ValueError, match="already registered"):
        mgr.register_core(CoreContext("core_1", OperationalState.ONLINE, []))

# Topology Validation Tests
def test_topology_valid_device_core():
    mgr = setup_manager()
    mgr.register_core(CoreContext("core_1", OperationalState.ONLINE, [SecurityMode.HYBRID]))
    mgr.register_edge(EdgeContext("edge_1", OperationalState.ONLINE, [SecurityMode.HYBRID], "core_1"))
    mgr.register_device(DeviceContext("dev_1", "iot", OperationalState.ONLINE, [SecurityMode.HYBRID], [], [], "edge_1"))
    
    ctx = mgr.create_communication_context("ctx_1", "dev_1", "core_1", SecurityMode.HYBRID)
    assert ctx is not None

def test_source_equals_dest_rejected():
    mgr = setup_manager()
    mgr.register_core(CoreContext("core_1", OperationalState.ONLINE, [SecurityMode.HYBRID]))
    with pytest.raises(ValueError, match="Source and destination cannot be the same entity"):
        mgr.create_communication_context("ctx_1", "core_1", "core_1", SecurityMode.HYBRID)

def test_topology_invalid_device_unrelated_core():
    mgr = setup_manager()
    mgr.register_core(CoreContext("core_1", OperationalState.ONLINE, [SecurityMode.HYBRID]))
    mgr.register_core(CoreContext("core_2", OperationalState.ONLINE, [SecurityMode.HYBRID]))
    mgr.register_edge(EdgeContext("edge_1", OperationalState.ONLINE, [SecurityMode.HYBRID], "core_1"))
    mgr.register_device(DeviceContext("dev_1", "iot", OperationalState.ONLINE, [SecurityMode.HYBRID], [], [], "edge_1"))
    
    with pytest.raises(ValueError, match="Device edge is not connected to destination core"):
        mgr.create_communication_context("ctx_1", "dev_1", "core_2", SecurityMode.HYBRID)

def test_topology_valid_edge_core():
    mgr = setup_manager()
    mgr.register_core(CoreContext("core_1", OperationalState.ONLINE, [SecurityMode.HYBRID]))
    mgr.register_edge(EdgeContext("edge_1", OperationalState.ONLINE, [SecurityMode.HYBRID], "core_1"))
    
    ctx = mgr.create_communication_context("ctx_1", "edge_1", "core_1", SecurityMode.HYBRID)
    assert ctx is not None

def test_topology_invalid_edge_unrelated_core():
    mgr = setup_manager()
    mgr.register_core(CoreContext("core_1", OperationalState.ONLINE, [SecurityMode.HYBRID]))
    mgr.register_core(CoreContext("core_2", OperationalState.ONLINE, [SecurityMode.HYBRID]))
    mgr.register_edge(EdgeContext("edge_1", OperationalState.ONLINE, [SecurityMode.HYBRID], "core_1"))
    
    with pytest.raises(ValueError, match="Edge is not connected to destination core"):
        mgr.create_communication_context("ctx_1", "edge_1", "core_2", SecurityMode.HYBRID)

def test_topology_unknown_entity():
    mgr = setup_manager()
    mgr.register_core(CoreContext("core_1", OperationalState.ONLINE, [SecurityMode.HYBRID]))
    with pytest.raises(ValueError, match="Source or destination entity does not exist"):
        mgr.create_communication_context("ctx_1", "unknown", "core_1", SecurityMode.HYBRID)

# Capability Validation Tests
def test_unsupported_mode_rejected():
    mgr = setup_manager()
    mgr.register_core(CoreContext("core_1", OperationalState.ONLINE, [SecurityMode.CLASSICAL]))
    mgr.register_edge(EdgeContext("edge_1", OperationalState.ONLINE, [SecurityMode.CLASSICAL], "core_1"))
    mgr.register_device(DeviceContext("dev_1", "iot", OperationalState.ONLINE, [SecurityMode.CLASSICAL], [], [], "edge_1"))
    
    with pytest.raises(ValueError, match="not supported by"):
        mgr.create_communication_context("ctx_1", "dev_1", "core_1", SecurityMode.HYBRID)

def test_unsupported_algorithm_rejected():
    mgr = setup_manager()
    mgr.register_core(CoreContext("core_1", OperationalState.ONLINE, [SecurityMode.CLASSICAL]))
    mgr.register_edge(EdgeContext("edge_1", OperationalState.ONLINE, [SecurityMode.CLASSICAL], "core_1"))
    mgr.register_device(DeviceContext("dev_1", "iot", OperationalState.ONLINE, [SecurityMode.CLASSICAL], ["ed25519"], [], "edge_1"))
    
    mgr.create_communication_context("ctx_1", "dev_1", "core_1", SecurityMode.CLASSICAL)
    
    with pytest.raises(ValueError, match="Algorithm mldsa is not supported"):
        mgr.update_security_context("ctx_1", active_algorithms=["mldsa"])

def test_supported_algorithm_accepted():
    mgr = setup_manager()
    mgr.register_core(CoreContext("core_1", OperationalState.ONLINE, [SecurityMode.CLASSICAL]))
    mgr.register_edge(EdgeContext("edge_1", OperationalState.ONLINE, [SecurityMode.CLASSICAL], "core_1"))
    mgr.register_device(DeviceContext("dev_1", "iot", OperationalState.ONLINE, [SecurityMode.CLASSICAL], ["ed25519"], [], "edge_1"))
    
    mgr.create_communication_context("ctx_1", "dev_1", "core_1", SecurityMode.CLASSICAL)
    mgr.update_security_context("ctx_1", active_algorithms=["ed25519"])
    assert mgr.comm_contexts["ctx_1"].security.active_algorithms == ["ed25519"]

# Metadata Security Validation Tests
def test_safe_metadata_accepted():
    validate_safe_metadata({"a": 1, "b": "str", "c": True, "d": None, "e": [1.5, {"nested": "safe"}]})

def test_unsafe_bytes_rejected():
    with pytest.raises(ValueError, match="Unsafe metadata type detected"):
        validate_safe_metadata({"a": b"secret"})

def test_nested_unsafe_rejected():
    with pytest.raises(ValueError, match="Unsafe metadata type detected"):
        validate_safe_metadata({"a": [1, 2, {"b": bytearray(b"secret")}]})

class DummyKey:
    pass

def test_arbitrary_object_metadata_rejected():
    with pytest.raises(ValueError, match="Unsafe metadata type detected"):
        validate_safe_metadata({"key": DummyKey()})

# Field Validation Tests
def test_unknown_security_context_field_rejected():
    mgr = setup_manager()
    mgr.register_core(CoreContext("core_1", OperationalState.ONLINE, [SecurityMode.HYBRID]))
    mgr.register_edge(EdgeContext("edge_1", OperationalState.ONLINE, [SecurityMode.HYBRID], "core_1"))
    mgr.create_communication_context("ctx_1", "edge_1", "core_1", SecurityMode.HYBRID)
    
    with pytest.raises(ValueError, match="Unknown or unsupported field"):
        mgr.update_security_context("ctx_1", malicious_field="inject")

def test_invalid_types_rejected():
    mgr = setup_manager()
    mgr.register_core(CoreContext("core_1", OperationalState.ONLINE, [SecurityMode.HYBRID]))
    mgr.register_edge(EdgeContext("edge_1", OperationalState.ONLINE, [SecurityMode.HYBRID], "core_1"))
    mgr.create_communication_context("ctx_1", "edge_1", "core_1", SecurityMode.HYBRID)
    
    with pytest.raises(ValueError, match="security_mode must be SecurityMode"):
        mgr.update_security_context("ctx_1", security_mode="HYBRID") 
        
    with pytest.raises(ValueError, match="auth_status must be AuthStatus"):
        mgr.update_security_context("ctx_1", auth_status="AUTHENTICATED")
        
    with pytest.raises(ValueError, match="encryption_active must be bool"):
        mgr.update_security_context("ctx_1", encryption_active="True")
        
    with pytest.raises(ValueError, match="session_id must be str or None"):
        mgr.update_security_context("ctx_1", session_id=123)
        
    with pytest.raises(ValueError, match="active_algorithms must be list"):
        mgr.update_security_context("ctx_1", active_algorithms="aes")

# State Transition Validation Tests
def test_invalid_state_transition_rejected():
    mgr = setup_manager()
    mgr.register_core(CoreContext("core_1", OperationalState.ONLINE, [SecurityMode.HYBRID]))
    mgr.register_edge(EdgeContext("edge_1", OperationalState.ONLINE, [SecurityMode.HYBRID], "core_1"))
    mgr.create_communication_context("ctx_1", "edge_1", "core_1", SecurityMode.HYBRID)
    
    with pytest.raises(ValueError, match="Invalid auth_status transition"):
        mgr.update_security_context("ctx_1", auth_status=AuthStatus.AUTHENTICATED)

def test_valid_authentication_state_progression():
    mgr = setup_manager()
    mgr.register_core(CoreContext("core_1", OperationalState.ONLINE, [SecurityMode.HYBRID]))
    mgr.register_edge(EdgeContext("edge_1", OperationalState.ONLINE, [SecurityMode.HYBRID], "core_1"))
    mgr.create_communication_context("ctx_1", "edge_1", "core_1", SecurityMode.HYBRID)
    
    mgr.update_security_context("ctx_1", auth_status=AuthStatus.AUTHENTICATING)
    assert mgr.comm_contexts["ctx_1"].security.auth_status == AuthStatus.AUTHENTICATING
    
    mgr.update_security_context("ctx_1", auth_status=AuthStatus.AUTHENTICATED)
    assert mgr.comm_contexts["ctx_1"].security.auth_status == AuthStatus.AUTHENTICATED

def test_valid_authentication_failure_transition():
    mgr = setup_manager()
    mgr.register_core(CoreContext("core_1", OperationalState.ONLINE, [SecurityMode.HYBRID]))
    mgr.register_edge(EdgeContext("edge_1", OperationalState.ONLINE, [SecurityMode.HYBRID], "core_1"))
    mgr.create_communication_context("ctx_1", "edge_1", "core_1", SecurityMode.HYBRID)
    
    mgr.update_security_context("ctx_1", auth_status=AuthStatus.AUTHENTICATING)
    mgr.update_security_context("ctx_1", auth_status=AuthStatus.FAILED)
    assert mgr.comm_contexts["ctx_1"].security.auth_status == AuthStatus.FAILED

def test_valid_recovery_from_failed():
    mgr = setup_manager()
    mgr.register_core(CoreContext("core_1", OperationalState.ONLINE, [SecurityMode.HYBRID]))
    mgr.register_edge(EdgeContext("edge_1", OperationalState.ONLINE, [SecurityMode.HYBRID], "core_1"))
    mgr.create_communication_context("ctx_1", "edge_1", "core_1", SecurityMode.HYBRID)
    
    mgr.update_security_context("ctx_1", auth_status=AuthStatus.AUTHENTICATING)
    mgr.update_security_context("ctx_1", auth_status=AuthStatus.FAILED)
    mgr.update_security_context("ctx_1", auth_status=AuthStatus.AUTHENTICATING)
    assert mgr.comm_contexts["ctx_1"].security.auth_status == AuthStatus.AUTHENTICATING

def test_valid_session_establishment_and_termination():
    mgr = setup_manager()
    mgr.register_core(CoreContext("core_1", OperationalState.ONLINE, [SecurityMode.HYBRID]))
    mgr.register_edge(EdgeContext("edge_1", OperationalState.ONLINE, [SecurityMode.HYBRID], "core_1"))
    mgr.create_communication_context("ctx_1", "edge_1", "core_1", SecurityMode.HYBRID)
    
    mgr.update_security_context("ctx_1", session_id="ses_123", encryption_active=True)
    assert mgr.comm_contexts["ctx_1"].security.session_id == "ses_123"
    assert mgr.comm_contexts["ctx_1"].security.encryption_active is True
    
    mgr.update_security_context("ctx_1", session_id=None, encryption_active=False)
    assert mgr.comm_contexts["ctx_1"].security.session_id is None
    assert mgr.comm_contexts["ctx_1"].security.encryption_active is False

def test_inconsistent_session_termination_rejected():
    mgr = setup_manager()
    mgr.register_core(CoreContext("core_1", OperationalState.ONLINE, [SecurityMode.HYBRID]))
    mgr.register_edge(EdgeContext("edge_1", OperationalState.ONLINE, [SecurityMode.HYBRID], "core_1"))
    mgr.create_communication_context("ctx_1", "edge_1", "core_1", SecurityMode.HYBRID)
    
    mgr.update_security_context("ctx_1", session_id="ses_123", encryption_active=True)
    
    # Attempting to clear session_id without clearing encryption_active must fail atomically
    with pytest.raises(ValueError, match="Inconsistent state"):
        mgr.update_security_context("ctx_1", session_id=None)
        
    # The context must remain unmodified
    assert mgr.comm_contexts["ctx_1"].security.session_id == "ses_123"
    assert mgr.comm_contexts["ctx_1"].security.encryption_active is True
    
    # Verify the event log does NOT contain a termination event from the failed call
    events = [r.event_type for r in mgr.telemetry.records if r.context_id == "ctx_1"]
    assert EnvironmentEventType.SESSION_TERMINATED.value not in events


# Telemetry tests
def test_telemetry_events_generated():
    mgr = setup_manager()
    mgr.register_core(CoreContext("core_1", OperationalState.ONLINE, [SecurityMode.CLASSICAL, SecurityMode.HYBRID]))
    mgr.register_edge(EdgeContext("edge_1", OperationalState.ONLINE, [SecurityMode.CLASSICAL, SecurityMode.HYBRID], "core_1"))
    
    mgr.create_communication_context("ctx_1", "edge_1", "core_1", SecurityMode.CLASSICAL)
    
    mgr.update_security_context("ctx_1", auth_status=AuthStatus.AUTHENTICATING)
    mgr.update_security_context("ctx_1", auth_status=AuthStatus.AUTHENTICATED)
    mgr.update_security_context("ctx_1", security_mode=SecurityMode.HYBRID)
    mgr.update_security_context("ctx_1", encryption_active=True, session_id="ses1")
    mgr.update_entity_state("edge_1", OperationalState.COMPROMISED)
    
    events = [r.event_type for r in mgr.telemetry.records]
    assert EnvironmentEventType.CONTEXT_CREATED.value in events
    assert EnvironmentEventType.AUTHENTICATION_STARTED.value in events
    assert EnvironmentEventType.AUTHENTICATION_SUCCESS.value in events
    assert EnvironmentEventType.SECURITY_MODE_CHANGED.value in events
    assert EnvironmentEventType.ENCRYPTION_ENABLED.value in events
    assert EnvironmentEventType.SESSION_ESTABLISHED.value in events
    assert EnvironmentEventType.OPERATIONAL_STATE_CHANGED.value in events

def test_telemetry_defensive_copy():
    mgr = setup_manager()
    mgr.register_core(CoreContext("core_1", OperationalState.ONLINE, [SecurityMode.CLASSICAL]))
    mgr.register_edge(EdgeContext("edge_1", OperationalState.ONLINE, [SecurityMode.CLASSICAL], "core_1"))
    mgr.create_communication_context("ctx_1", "edge_1", "core_1", SecurityMode.CLASSICAL)
    
    meta = {"state": "normal"}
    mgr.update_security_context("ctx_1", metadata=meta)
    
    meta["state"] = "modified"
    
    # Check the last telemetry record
    last_record = mgr.telemetry.records[-1]
    assert last_record.metadata["metadata"]["state"] == "normal"

def test_no_secrets_in_snapshot_cannot_serialize_bytes():
    mgr = setup_manager()
    mgr.register_core(CoreContext("core_1", OperationalState.ONLINE, [SecurityMode.CLASSICAL]))
    mgr.register_edge(EdgeContext("edge_1", OperationalState.ONLINE, [SecurityMode.CLASSICAL], "core_1"))
    mgr.create_communication_context("ctx_1", "edge_1", "core_1", SecurityMode.CLASSICAL)
    
    with pytest.raises(ValueError):
        mgr.update_security_context("ctx_1", metadata={"key": b"secret"})
        
    s = json.dumps(mgr.get_snapshot())
    assert "secret" not in s

# Context isolation
def test_context_isolation():
    mgr = setup_manager()
    mgr.register_core(CoreContext("core_1", OperationalState.ONLINE, [SecurityMode.CLASSICAL, SecurityMode.PQC]))
    mgr.register_edge(EdgeContext("edge_1", OperationalState.ONLINE, [SecurityMode.CLASSICAL], "core_1"))
    mgr.register_edge(EdgeContext("edge_2", OperationalState.ONLINE, [SecurityMode.PQC], "core_1"))
    
    mgr.create_communication_context("ctx_1", "edge_1", "core_1", SecurityMode.CLASSICAL)
    mgr.create_communication_context("ctx_2", "edge_2", "core_1", SecurityMode.PQC)
    
    mgr.update_security_context("ctx_1", auth_status=AuthStatus.AUTHENTICATING)
    mgr.update_security_context("ctx_1", auth_status=AuthStatus.AUTHENTICATED)
    
    assert mgr.comm_contexts["ctx_1"].security.auth_status == AuthStatus.AUTHENTICATED
    assert mgr.comm_contexts["ctx_2"].security.auth_status == AuthStatus.UNAUTHENTICATED
