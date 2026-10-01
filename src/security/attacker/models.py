from enum import Enum
from dataclasses import dataclass, field
from typing import List, Optional, Any, Dict
from src.security.attacker.intensity import AttackIntensity

class AttackType(Enum):
    AUTHENTICATION_ATTACK = "AUTHENTICATION_ATTACK"
    REPLAY_ATTACK = "REPLAY_ATTACK"
    MESSAGE_TAMPERING_ATTACK = "MESSAGE_TAMPERING_ATTACK"
    SESSION_ABUSE_ATTACK = "SESSION_ABUSE_ATTACK"
    RESOURCE_PRESSURE_ATTACK = "RESOURCE_PRESSURE_ATTACK"
    COORDINATED_ATTACK = "COORDINATED_ATTACK"

class AttackStatus(Enum):
    SCHEDULED = "SCHEDULED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

@dataclass(frozen=True)
class AttackerProfile:
    attacker_id: str
    capabilities: List[AttackType]
    max_intensity: AttackIntensity

@dataclass
class AttackScenario:
    attack_id: str
    attack_type: AttackType
    attacker_id: str
    target_id: str
    context_id: str
    start_tick: int
    duration_ticks: int
    intensity: AttackIntensity
    sub_scenarios: Optional[List['AttackScenario']] = None
    
    def __post_init__(self):
        if self.start_tick < 0:
            raise ValueError("start_tick cannot be negative")
        if self.duration_ticks < 0:
            raise ValueError("duration_ticks cannot be negative")
        if self.attacker_id == self.target_id:
            raise ValueError("attacker_id cannot be the same as target_id")
        if not isinstance(self.attack_type, AttackType):
            raise ValueError("Invalid attack_type")
        if not isinstance(self.intensity, AttackIntensity):
            raise ValueError("Invalid intensity")

@dataclass
class AttackGroundTruth:
    attack_id: str
    attack_type: AttackType
    attacker_id: str
    target_id: str
    context_id: str
    start_tick: int
    end_tick: int
    intended_intensity: AttackIntensity
    attack_scheduled: bool = False
    attack_attempted: bool = False
    attack_injected: bool = False
    attempts_generated: int = 0
    events_generated: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "attack_id": self.attack_id,
            "attack_type": self.attack_type.value,
            "attacker_id": self.attacker_id,
            "target_id": self.target_id,
            "context_id": self.context_id,
            "start_tick": self.start_tick,
            "end_tick": self.end_tick,
            "intended_intensity": self.intended_intensity.value,
            "attack_scheduled": self.attack_scheduled,
            "attack_attempted": self.attack_attempted,
            "attack_injected": self.attack_injected,
            "attempts_generated": self.attempts_generated,
            "events_generated": self.events_generated
        }

@dataclass
class AttackInjectionResult:
    attack_id: str
    scheduled: bool
    started: bool
    completed: bool
    attempts_generated: int
    events_generated: int
    genuine_attempts: int = 0
    synthetic_attempts: int = 0
    injection_errors: List[str] = field(default_factory=list)
