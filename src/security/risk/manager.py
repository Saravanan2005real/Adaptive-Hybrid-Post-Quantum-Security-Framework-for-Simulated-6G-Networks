import copy
from typing import Dict, List, Any
from src.security.risk.models import RiskAssessment, RiskLevel, RiskEventType
from src.security.risk.scorer import calculate_entity_risk, calculate_context_risk
from src.security.environment.manager import EnvironmentManager
from src.events import EventLogger, EventType

class RiskManager:
    def __init__(self, env_manager: EnvironmentManager, logger: EventLogger = None):
        self.env = env_manager
        self.logger = logger
        self.history: List[RiskAssessment] = []
        # Store the last known risk level per entity to detect changes
        self.last_known_levels: Dict[str, RiskLevel] = {}
        
    def _handle_assessment(self, assessment: RiskAssessment):
        # Defensive copy for append-only history
        safe_assessment = copy.deepcopy(assessment)
        self.history.append(safe_assessment)
        
        entity_id = safe_assessment.entity_id
        current_level = safe_assessment.risk_level
        
        if self.logger:
            self.logger.log(
                EventType.RISK_ASSESSMENT_CREATED,
                safe_assessment.timestamp,
                entity_id=entity_id,
                risk_score=safe_assessment.risk_score,
                risk_level=current_level.value
            )
            
            previous_level = self.last_known_levels.get(entity_id)
            if previous_level and previous_level != current_level:
                self.logger.log(
                    EventType.RISK_LEVEL_CHANGED,
                    safe_assessment.timestamp,
                    entity_id=entity_id,
                    old_level=previous_level.value,
                    new_level=current_level.value
                )
                
        self.last_known_levels[entity_id] = current_level

    def evaluate_entity(self, entity_id: str) -> RiskAssessment:
        if not self.env.entity_exists(entity_id):
            raise ValueError(f"Entity {entity_id} does not exist in environment")
            
        entity = self.env.get_entity(entity_id)
        assessment = calculate_entity_risk(entity, entity_id, self.env.current_tick)
        
        self._handle_assessment(assessment)
        return assessment
        
    def evaluate_context(self, context_id: str, telemetry_window_ticks: int = 100) -> RiskAssessment:
        if context_id not in self.env.comm_contexts:
            raise ValueError(f"Context {context_id} does not exist in environment")
            
        ctx = self.env.comm_contexts[context_id]
        
        # Filter telemetry to the evaluation window safely (reading only)
        min_tick = max(0, self.env.current_tick - telemetry_window_ticks)
        relevant_telemetry = [
            r for r in self.env.telemetry.records 
            if r.timestamp >= min_tick and r.context_id == context_id
        ]
        
        assessment = calculate_context_risk(ctx.security, context_id, relevant_telemetry, self.env.current_tick)
        
        self._handle_assessment(assessment)
        return assessment
