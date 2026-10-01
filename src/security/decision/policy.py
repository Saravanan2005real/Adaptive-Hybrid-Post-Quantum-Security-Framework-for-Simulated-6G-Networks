from src.security.risk.models import RiskLevel
from src.security.environment.models import SecurityMode

# RESEARCH-PROTOTYPE POLICY ASSUMPTIONS
# These map risk levels to recommended prototype security modes.
DEFAULT_POLICY_MAP = {
    RiskLevel.LOW: SecurityMode.CLASSICAL,
    RiskLevel.MEDIUM: SecurityMode.PQC,
    RiskLevel.HIGH: SecurityMode.HYBRID,
    RiskLevel.CRITICAL: SecurityMode.HYBRID
}

def get_policy_recommendation(level: RiskLevel) -> SecurityMode:
    if not isinstance(level, RiskLevel):
        raise ValueError("Invalid risk level type")
    if level not in DEFAULT_POLICY_MAP:
        raise ValueError(f"Unknown risk level in policy: {level}")
    return DEFAULT_POLICY_MAP[level]

def get_policy_rule_description(level: RiskLevel) -> str:
    mode = get_policy_recommendation(level)
    return f"{level.name} -> {mode.name}"

def get_decision_reason(level: RiskLevel) -> str:
    if level == RiskLevel.LOW:
        return "LOW risk permits the baseline CLASSICAL security mode."
    elif level == RiskLevel.MEDIUM:
        return "MEDIUM risk requires stronger post-quantum protection; PQC mode selected."
    elif level == RiskLevel.HIGH:
        return "HIGH risk requires hybrid classical + post-quantum protection; HYBRID mode selected."
    elif level == RiskLevel.CRITICAL:
        return "CRITICAL risk requires the strongest available prototype security mode; HYBRID mode selected."
    else:
        raise ValueError("Unknown risk level")
