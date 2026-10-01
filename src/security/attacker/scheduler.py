from typing import List, Dict, Any, Optional
from src.security.attacker.models import AttackScenario, AttackerProfile

class AttackScheduler:
    def __init__(self):
        self.scenarios: List[AttackScenario] = []
        self.attacker_profiles: Dict[str, AttackerProfile] = {}
        self.active_contexts: List[str] = []
        self.active_entities: List[str] = []

    def register_attacker(self, profile: AttackerProfile):
        self.attacker_profiles[profile.attacker_id] = profile

    def update_environment(self, entities: List[str], contexts: List[str]):
        self.active_entities = entities
        self.active_contexts = contexts

    def schedule_attack(self, scenario: AttackScenario):
        # Validation
        if scenario.attacker_id not in self.attacker_profiles:
            raise ValueError(f"Unknown attacker: {scenario.attacker_id}")
        
        profile = self.attacker_profiles[scenario.attacker_id]
        if scenario.attack_type not in profile.capabilities:
            raise ValueError(f"Attacker {scenario.attacker_id} cannot perform {scenario.attack_type}")
            
        if scenario.target_id not in self.active_entities:
            raise ValueError(f"Unknown target entity: {scenario.target_id}")
            
        if scenario.context_id not in self.active_contexts:
            raise ValueError(f"Unknown context: {scenario.context_id}")

        self.scenarios.append(scenario)
        # Order by start_tick
        self.scenarios.sort(key=lambda s: s.start_tick)

    def get_attacks_for_tick(self, tick: int) -> List[AttackScenario]:
        active_attacks = []
        for s in self.scenarios:
            if s.start_tick <= tick <= s.start_tick + s.duration_ticks:
                active_attacks.append(s)
        return active_attacks
