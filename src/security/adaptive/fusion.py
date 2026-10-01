from typing import Tuple
from src.security.risk.models import RiskLevel
from src.security.risk.scorer import determine_risk_level

class RiskFusion:
    def __init__(self, rule_weight: float = 0.5, ml_weight: float = 0.5):
        if rule_weight < 0 or ml_weight < 0:
            raise ValueError("Weights must be non-negative")
        if not (0.999 <= rule_weight + ml_weight <= 1.001):
            raise ValueError("Weights must sum to 1")
            
        self.rule_weight = rule_weight
        self.ml_weight = ml_weight
        
    def fuse(self, rule_score: float, ml_score: float) -> Tuple[float, RiskLevel, float]:
        fused = self.rule_weight * rule_score + self.ml_weight * ml_score
        fused = max(0.0, min(100.0, fused))
        
        disagreement = abs(rule_score - ml_score)
        level = determine_risk_level(fused)
        
        return fused, level, disagreement
