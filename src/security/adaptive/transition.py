from typing import Dict, Optional, Tuple
from src.security.environment.models import SecurityMode
from src.events import EventLogger, EventType

class TransitionManager:
    def __init__(self, cooldown_ticks: int = 3, downgrade_cycles: int = 3, logger: Optional[EventLogger] = None):
        self.cooldown_ticks = cooldown_ticks
        self.downgrade_cycles = downgrade_cycles
        self.logger = logger
        
        # Tracking states
        self.last_transition_tick: Dict[str, int] = {}
        self.downgrade_counters: Dict[str, int] = {}
        self.pending_downgrade_mode: Dict[str, Optional[SecurityMode]] = {}
        
    def _is_escalation(self, current: SecurityMode, target: SecurityMode) -> bool:
        hierarchy = {SecurityMode.CLASSICAL: 1, SecurityMode.PQC: 2, SecurityMode.HYBRID: 3}
        return hierarchy[target] > hierarchy[current]
        
    def evaluate_transition(self, context_id: str, current_tick: int, current_mode: SecurityMode, target_mode: SecurityMode) -> Tuple[bool, Optional[str]]:
        """
        Evaluates hysteresis and cooldown constraints.
        Returns (is_allowed, suppression_reason)
        """
        if current_mode == target_mode:
            self.downgrade_counters[context_id] = 0
            self.pending_downgrade_mode[context_id] = None
            return False, "Mode already active"
            
        is_escalation = self._is_escalation(current_mode, target_mode)
        
        # Check cooldown
        last_tick = self.last_transition_tick.get(context_id, -self.cooldown_ticks - 1)
        if current_tick - last_tick < self.cooldown_ticks:
            return False, "Cooldown active"
            
        if is_escalation:
            # Immediate escalation
            self.downgrade_counters[context_id] = 0
            self.pending_downgrade_mode[context_id] = None
            return True, None
            
        else:
            # Downgrade hysteresis
            pending = self.pending_downgrade_mode.get(context_id)
            if pending != target_mode:
                self.pending_downgrade_mode[context_id] = target_mode
                self.downgrade_counters[context_id] = 1
            else:
                self.downgrade_counters[context_id] += 1
                
            if self.downgrade_counters[context_id] >= self.downgrade_cycles:
                self.downgrade_counters[context_id] = 0
                self.pending_downgrade_mode[context_id] = None
                return True, None
            else:
                if self.logger:
                    self.logger.log(EventType.SECURITY_DOWNGRADE_PENDING, current_tick, context_id=context_id, target_mode=target_mode.value, current_count=self.downgrade_counters[context_id])
                return False, "Downgrade hysteresis"

    def mark_transition(self, context_id: str, current_tick: int):
        self.last_transition_tick[context_id] = current_tick
        self.downgrade_counters[context_id] = 0
        self.pending_downgrade_mode[context_id] = None
