from enum import Enum, auto
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

class SecurityMode(Enum):
    CLASSICAL = "CLASSICAL"
    PQC = "PQC"
    HYBRID = "HYBRID"

class OperationalState(Enum):
    ONLINE = "ONLINE"
    OFFLINE = "OFFLINE"
    COMPROMISED = "COMPROMISED"
    DEGRADED = "DEGRADED"

class AuthStatus(Enum):
    UNAUTHENTICATED = "UNAUTHENTICATED"
    AUTHENTICATING = "AUTHENTICATING"
    AUTHENTICATED = "AUTHENTICATED"
    FAILED = "FAILED"

class EnvironmentEventType(Enum):
    CONTEXT_CREATED = "CONTEXT_CREATED"
    AUTHENTICATION_STARTED = "AUTHENTICATION_STARTED"
    AUTHENTICATION_SUCCESS = "AUTHENTICATION_SUCCESS"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    SESSION_ESTABLISHED = "SESSION_ESTABLISHED"
    SESSION_TERMINATED = "SESSION_TERMINATED"
    ENCRYPTION_ENABLED = "ENCRYPTION_ENABLED"
    ENCRYPTION_DISABLED = "ENCRYPTION_DISABLED"
    SECURITY_MODE_CHANGED = "SECURITY_MODE_CHANGED"
    OPERATIONAL_STATE_CHANGED = "OPERATIONAL_STATE_CHANGED"
    CONTEXT_UPDATED = "CONTEXT_UPDATED"


    
@dataclass
class DeviceContext:
    device_id: str
    device_type: str
    operational_state: OperationalState
    supported_security_modes: List[SecurityMode]
    supported_classical_crypto: List[str]
    supported_pqc_crypto: List[str]
    connected_edge_id: Optional[str] = None
    
@dataclass
class EdgeContext:
    edge_id: str
    operational_state: OperationalState
    supported_security_modes: List[SecurityMode]
    connected_core_id: Optional[str] = None
    connected_device_ids: List[str] = field(default_factory=list)

@dataclass
class CoreContext:
    core_id: str
    operational_state: OperationalState
    supported_security_modes: List[SecurityMode]
    connected_edge_ids: List[str] = field(default_factory=list)

@dataclass
class SecurityContext:
    security_mode: SecurityMode
    auth_status: AuthStatus
    encryption_active: bool
    session_id: Optional[str] = None
    active_algorithms: List[str] = field(default_factory=list)
    last_activity_tick: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class CommunicationContext:
    context_id: str
    source_id: str
    destination_id: str
    security: SecurityContext
    creation_tick: int
    last_activity_tick: int
    messages_exchanged: int = 0
