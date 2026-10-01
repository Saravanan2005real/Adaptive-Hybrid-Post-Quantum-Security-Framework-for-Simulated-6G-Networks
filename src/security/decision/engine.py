import copy
from typing import List, Optional
from src.security.risk.models import RiskAssessment, RiskLevel
from src.security.risk.scorer import determine_risk_level
from src.security.environment.models import SecurityMode
from src.security.decision.models import DecisionResult
from src.security.decision.policy import (
    get_policy_recommendation, get_policy_rule_description, get_decision_reason
)
from src.events import EventLogger, EventType
from src.security.risk.manager import RiskManager

class DecisionEngine:
    def __init__(self, logger: Optional[EventLogger] = None):
        self.logger = logger
        self.history: List[DecisionResult] = []
        
    def _validate_assessment(self, assessment: RiskAssessment):
        if not isinstance(assessment, RiskAssessment):
            raise ValueError("Invalid RiskAssessment object")
        
        # Check if score is valid
        if assessment.risk_score < 0.0 or assessment.risk_score > 100.0:
            raise ValueError(f"Invalid risk score: {assessment.risk_score}")
            
        # Check if level is valid type
        if not isinstance(assessment.risk_level, RiskLevel):
            raise ValueError("Invalid risk level type")
            
        # Verify internal consistency
        expected_level = determine_risk_level(assessment.risk_score)
        if assessment.risk_level != expected_level:
            raise ValueError(f"Inconsistent risk assessment: score {assessment.risk_score} does not match level {assessment.risk_level}")
            
        if not assessment.entity_id:
            raise ValueError("Missing entity_id in risk assessment")
            
    def evaluate_decision(self, assessment: RiskAssessment, current_mode: SecurityMode, context_id: str) -> DecisionResult:
        self._validate_assessment(assessment)
        
        if not isinstance(current_mode, SecurityMode):
            raise ValueError("Invalid current security mode type")
            
        if not context_id:
            raise ValueError("Missing context_id")
            
        recommended_mode = get_policy_recommendation(assessment.risk_level)
        requires_transition = (current_mode != recommended_mode)
        
        result = DecisionResult(
            entity_id=assessment.entity_id,
            context_id=context_id,
            risk_score=assessment.risk_score,
            risk_level=assessment.risk_level,
            current_security_mode=current_mode,
            recommended_security_mode=recommended_mode,
            decision_reason=get_decision_reason(assessment.risk_level),
            policy_rule=get_policy_rule_description(assessment.risk_level),
            timestamp=assessment.timestamp,
            mode_changed=requires_transition,
            requires_transition=requires_transition
        )
        
        safe_result = copy.deepcopy(result)
        self.history.append(safe_result)
        
        if self.logger:
            self.logger.log(
                EventType.SECURITY_DECISION_CREATED,
                result.timestamp,
                entity_id=result.entity_id,
                context_id=result.context_id,
                risk_score=result.risk_score,
                risk_level=result.risk_level.value,
                current_mode=result.current_security_mode.value,
                recommended_mode=result.recommended_security_mode.value,
                reason=result.decision_reason,
                policy_rule=result.policy_rule
            )
            
            if requires_transition:
                self.logger.log(
                    EventType.SECURITY_MODE_CHANGE_RECOMMENDED,
                    result.timestamp,
                    entity_id=result.entity_id,
                    context_id=result.context_id,
                    old_mode=result.current_security_mode.value,
                    new_mode=result.recommended_security_mode.value
                )
                
        return result
        
    def evaluate_and_decide(self, context_id: str, risk_manager: RiskManager) -> DecisionResult:
        if context_id not in risk_manager.env.comm_contexts:
            raise ValueError(f"Context {context_id} does not exist in environment")
            
        ctx = risk_manager.env.comm_contexts[context_id]
        current_mode = ctx.security.security_mode
        
        assessment = risk_manager.evaluate_context(context_id)
        
        # Also need entity risk if appropriate, but the prompt says evaluate risk using Step 8.
        # Let's just use context assessment since the decision operates on a single assessment 
        # (could be combined if needed, but keeping it simple).
        return self.evaluate_decision(assessment, current_mode, context_id)
