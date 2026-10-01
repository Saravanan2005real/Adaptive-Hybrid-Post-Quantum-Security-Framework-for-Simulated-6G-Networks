from typing import Optional, List
import copy
from src.security.environment.manager import EnvironmentManager
from src.security.risk.manager import RiskManager
from src.security.ml_risk.predictor import MLRiskPredictorAPI
from src.security.adaptive.models import AdaptiveDecisionResult
from src.security.adaptive.fusion import RiskFusion
from src.security.adaptive.policy import AdaptiveSecurityPolicy
from src.security.adaptive.transition import TransitionManager
from src.events import EventLogger, EventType

class AdaptiveSecurityEngine:
    def __init__(
        self,
        env_manager: EnvironmentManager,
        risk_manager: RiskManager,
        ml_predictor: MLRiskPredictorAPI,
        logger: Optional[EventLogger] = None,
        rule_weight: float = 0.5,
        ml_weight: float = 0.5,
        cooldown_ticks: int = 3,
        downgrade_cycles: int = 3
    ):
        self.env = env_manager
        self.risk = risk_manager
        self.ml = ml_predictor
        self.logger = logger
        self.fusion = RiskFusion(rule_weight, ml_weight)
        self.policy = AdaptiveSecurityPolicy()
        self.transition = TransitionManager(cooldown_ticks, downgrade_cycles, logger)
        
        self._history: List[AdaptiveDecisionResult] = []
        self.perf_metrics = {
            "risk_calc": [],
            "ml_inference": [],
            "fusion": [],
            "policy_hysteresis": [],
            "transition": [],
            "total_eval": []
        }

    @property
    def history(self) -> List[AdaptiveDecisionResult]:
        return list(self._history)

    def evaluate(self, context_id: str) -> AdaptiveDecisionResult:
        import time
        start_eval = time.perf_counter()
        
        if context_id not in self.env.comm_contexts:
            raise ValueError(f"Context {context_id} does not exist")
            
        ctx = self.env.comm_contexts[context_id]
        current_tick = self.env.current_tick
        entity_id = ctx.source_id
        
        # 1. Step 8 Risk (Context + Entity Combined, matching Step 10 reference score)
        t0 = time.perf_counter()
        ctx_assessment = self.risk.evaluate_context(context_id)
        ent_assessment = self.risk.evaluate_entity(entity_id)
        combined_rule_score = min(100.0, ctx_assessment.risk_score + ent_assessment.risk_score)
        
        from src.security.risk.scorer import determine_risk_level
        combined_rule_level = determine_risk_level(combined_rule_score)
        self.perf_metrics["risk_calc"].append(time.perf_counter() - t0)
        
        # 2. Step 10 ML Risk
        t0 = time.perf_counter()
        try:
            ml_score, ml_level = self.ml.predict_context_risk(self.env, context_id)
        except ValueError as e:
            if self.logger:
                self.logger.log(EventType.SECURITY_TRANSITION_FAILED, current_tick, context_id=context_id, reason=f"ML prediction failed: {str(e)}")
            raise ValueError(f"ML prediction failed: {e}")
        self.perf_metrics["ml_inference"].append(time.perf_counter() - t0)
            
        # 3. Fuse Risk
        t0 = time.perf_counter()
        fused_score, fused_level, disagreement = self.fusion.fuse(combined_rule_score, ml_score)
        self.perf_metrics["fusion"].append(time.perf_counter() - t0)
        
        if self.logger:
            self.logger.log(
                EventType.ADAPTIVE_RISK_EVALUATED,
                current_tick,
                context_id=context_id,
                rule_score=combined_rule_score,
                ml_score=ml_score,
                fused_score=fused_score,
                disagreement=disagreement
            )
            
        # 4. Policy Target
        t0 = time.perf_counter()
        target_mode = self.policy.determine_target_mode(fused_level)
        current_mode = ctx.security.security_mode
        
        if self.logger:
            self.logger.log(
                EventType.ADAPTIVE_DECISION_CREATED,
                current_tick,
                context_id=context_id,
                target_mode=target_mode.value
            )
        
        # 5. Transition Check
        allowed, suppression_reason = self.transition.evaluate_transition(context_id, current_tick, current_mode, target_mode)
        self.perf_metrics["policy_hysteresis"].append(time.perf_counter() - t0)
        
        transition_applied = False
        
        t0 = time.perf_counter()
        if allowed:
            if self.logger:
                self.logger.log(EventType.SECURITY_TRANSITION_STARTED, current_tick, context_id=context_id, from_mode=current_mode.value, to_mode=target_mode.value)
            
            # 6. Apply Transition
            # Atomic update via EnvironmentManager
            try:
                self.env.update_security_context(context_id, security_mode=target_mode)
                self.transition.mark_transition(context_id, current_tick)
                transition_applied = True
                if self.logger:
                    self.logger.log(EventType.SECURITY_TRANSITION_COMPLETED, current_tick, context_id=context_id, new_mode=target_mode.value)
            except ValueError as e:
                suppression_reason = f"Transition failed: {str(e)}"
                if self.logger:
                    self.logger.log(EventType.SECURITY_TRANSITION_FAILED, current_tick, context_id=context_id, reason=suppression_reason)
        else:
            if current_mode != target_mode:
                if self.logger:
                    self.logger.log(EventType.SECURITY_TRANSITION_SUPPRESSED, current_tick, context_id=context_id, target_mode=target_mode.value, reason=suppression_reason)
        self.perf_metrics["transition"].append(time.perf_counter() - t0)
                    
        result = AdaptiveDecisionResult(
            timestamp=current_tick,
            context_id=context_id,
            entity_id=entity_id,
            rule_risk_score=combined_rule_score,
            rule_risk_level=combined_rule_level,
            ml_risk_score=ml_score,
            ml_risk_level=ml_level,
            fused_risk_score=fused_score,
            fused_risk_level=fused_level,
            risk_disagreement=disagreement,
            current_security_mode=current_mode,
            recommended_security_mode=target_mode,
            transition_required=(current_mode != target_mode),
            transition_applied=transition_applied,
            suppression_reason=suppression_reason
        )
        
        self._history.append(result)
            
        self.perf_metrics["total_eval"].append(time.perf_counter() - start_eval)
        return result
