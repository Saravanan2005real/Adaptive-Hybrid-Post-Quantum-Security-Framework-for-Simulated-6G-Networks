from src.security.risk.models import RiskLevel
from src.security.environment.models import SecurityMode
from src.security.decision.policy import get_policy_recommendation

class AdaptiveSecurityPolicy:
    def determine_target_mode(self, fused_level: RiskLevel) -> SecurityMode:
        """
        Determines the target security mode for a given fused risk level.
        Uses the exact same mapping as Step 9 policy rules.
        """
        return get_policy_recommendation(fused_level)
