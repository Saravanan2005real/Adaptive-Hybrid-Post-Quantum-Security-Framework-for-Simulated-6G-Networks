import random
from typing import Dict, List, Any
from src.events import EventLogger, EventType
from src.security.manager import SecurityManager, ProtectedMessagePayload
from src.security.attacker.models import (
    AttackScenario, AttackType, AttackIntensity, AttackGroundTruth, AttackInjectionResult
)
from src.security.attacker.scheduler import AttackScheduler

class AttackerSimulator:
    def __init__(self, security_manager: SecurityManager, logger: EventLogger, seed: int = 42):
        self.security_manager = security_manager
        self.logger = logger
        self.rng = random.Random(seed)
        self.scheduler = AttackScheduler()
        self.ground_truths: Dict[str, AttackGroundTruth] = {}
        
        # State to aid attacks
        self.captured_messages: List[Dict[str, Any]] = []

    def set_environment(self, entities: List[str], contexts: List[str]):
        self.scheduler.update_environment(entities, contexts)

    def schedule_attack(self, scenario: AttackScenario):
        self.scheduler.schedule_attack(scenario)
        gt = AttackGroundTruth(
            attack_id=scenario.attack_id,
            attack_type=scenario.attack_type,
            attacker_id=scenario.attacker_id,
            target_id=scenario.target_id,
            context_id=scenario.context_id,
            start_tick=scenario.start_tick,
            end_tick=scenario.start_tick + scenario.duration_ticks,
            intended_intensity=scenario.intensity,
            attack_scheduled=True
        )
        self.ground_truths[scenario.attack_id] = gt
        self.logger.log(
            EventType.ATTACK_SCHEDULED,
            timestamp=scenario.start_tick,
            attack_id=scenario.attack_id,
            attack_type=scenario.attack_type.value,
            attacker_id=scenario.attacker_id,
            target_id=scenario.target_id
        )

    def capture_message(self, sender_id: str, receiver_id: str, payload: ProtectedMessagePayload):
        self.captured_messages.append({
            "sender_id": sender_id,
            "receiver_id": receiver_id,
            "payload": payload
        })

    def process_tick(self, tick: int) -> List[AttackInjectionResult]:
        results = []
        active_attacks = self.scheduler.get_attacks_for_tick(tick)
        
        for scenario in active_attacks:
            gt = self.ground_truths[scenario.attack_id]
            if tick == scenario.start_tick:
                self.logger.log(
                    EventType.ATTACK_STARTED,
                    timestamp=tick,
                    attack_id=scenario.attack_id,
                    attack_type=scenario.attack_type.value,
                    attacker_id=scenario.attacker_id,
                    target_id=scenario.target_id
                )

            gt.attack_attempted = True
            
            # Determine intensity (attempts per tick)
            attempts = 1
            if scenario.intensity == AttackIntensity.LOW:
                attempts = 1
            elif scenario.intensity == AttackIntensity.MEDIUM:
                attempts = 5
            elif scenario.intensity == AttackIntensity.HIGH:
                attempts = 20

            injected = False
            errors = []
            
            genuine_attempts = 0
            synthetic_attempts = 0
            
            # Determine what attacks to run (including coordinated attacks)
            attacks_to_run = []
            if scenario.attack_type == AttackType.COORDINATED_ATTACK and scenario.sub_scenarios:
                attacks_to_run.extend(scenario.sub_scenarios)
            else:
                attacks_to_run.append(scenario)

            for sub_scenario in attacks_to_run:
                try:
                    for _ in range(attempts):
                        self.logger.log(
                            EventType.ATTACK_ATTEMPTED,
                            timestamp=tick,
                            attack_id=sub_scenario.attack_id,
                            attack_type=sub_scenario.attack_type.value
                        )
                        gt.attempts_generated += 1
                        
                        injected_flag, kind = self._execute_attack(sub_scenario, tick)
                        if kind == "genuine":
                            genuine_attempts += 1
                        elif kind == "synthetic":
                            synthetic_attempts += 1
                            
                        if injected_flag:
                            injected = True
                            gt.events_generated += 1
                            self.logger.log(
                                EventType.ATTACK_INJECTED,
                                timestamp=tick,
                                attack_id=sub_scenario.attack_id,
                                attack_type=sub_scenario.attack_type.value
                            )
                except Exception as e:
                    errors.append(str(e))
            
            if injected:
                gt.attack_injected = True
                
            if tick == scenario.start_tick + scenario.duration_ticks:
                self.logger.log(
                    EventType.ATTACK_COMPLETED,
                    timestamp=tick,
                    attack_id=scenario.attack_id,
                    attack_type=scenario.attack_type.value
                )
                
            results.append(AttackInjectionResult(
                attack_id=scenario.attack_id,
                scheduled=True,
                started=True,
                completed=(tick == scenario.start_tick + scenario.duration_ticks),
                attempts_generated=attempts * len(attacks_to_run),
                events_generated=gt.events_generated,
                genuine_attempts=genuine_attempts,
                synthetic_attempts=synthetic_attempts,
                injection_errors=errors
            ))
            
        return results

    def _execute_attack(self, scenario: AttackScenario, tick: int) -> tuple[bool, str]:
        if scenario.attack_type == AttackType.AUTHENTICATION_ATTACK:
            # Simulate authentication failure by providing unknown/attacker ID
            self.security_manager.authenticate_and_exchange(scenario.attacker_id, scenario.target_id, tick)
            return True, "genuine"
            
        elif scenario.attack_type == AttackType.REPLAY_ATTACK:
            # We need a captured message for the target
            candidates = [m for m in self.captured_messages if m["receiver_id"] == scenario.target_id or m["sender_id"] == scenario.target_id]
            if not candidates:
                # If no message captured, we create a dummy one with a random nonce to trigger rejection
                dummy_payload = ProtectedMessagePayload(
                    nonce=self.rng.randbytes(12),
                    ciphertext=self.rng.randbytes(32),
                    associated_data=f"{scenario.attacker_id}->{scenario.target_id}".encode()
                )
                try:
                    self.security_manager.decrypt_message(scenario.attacker_id, scenario.target_id, dummy_payload, tick)
                except Exception:
                    pass
                return True, "synthetic"
                
            msg = self.rng.choice(candidates)
            try:
                self.security_manager.decrypt_message(msg["sender_id"], msg["receiver_id"], msg["payload"], tick)
            except Exception:
                # Expecting ValueError("Replay detected")
                pass
            return True, "genuine"
            
        elif scenario.attack_type == AttackType.MESSAGE_TAMPERING_ATTACK:
            candidates = [m for m in self.captured_messages if m["receiver_id"] == scenario.target_id or m["sender_id"] == scenario.target_id]
            if not candidates:
                dummy_payload = ProtectedMessagePayload(
                    nonce=self.rng.randbytes(12),
                    ciphertext=self.rng.randbytes(32),
                    associated_data=f"{scenario.attacker_id}->{scenario.target_id}".encode()
                )
                try:
                    self.security_manager.decrypt_message(scenario.attacker_id, scenario.target_id, dummy_payload, tick)
                except Exception:
                    pass
                return True, "synthetic"
                
            msg = self.rng.choice(candidates)
            tampered_payload = ProtectedMessagePayload(
                nonce=msg["payload"].nonce,
                ciphertext=msg["payload"].ciphertext[:-1] + bytes([msg["payload"].ciphertext[-1] ^ 0xFF]),
                associated_data=msg["payload"].associated_data,
                session_id=msg["payload"].session_id
            )
            try:
                self.security_manager.decrypt_message(msg["sender_id"], msg["receiver_id"], tampered_payload, tick)
            except Exception:
                # Expecting ValueError for MAC check failed
                pass
            return True, "genuine"
            
        elif scenario.attack_type == AttackType.SESSION_ABUSE_ATTACK:
            # Repeated session establishment
            self.security_manager.authenticate_and_exchange(scenario.attacker_id, scenario.target_id, tick)
            return True, "genuine"
            
        elif scenario.attack_type == AttackType.RESOURCE_PRESSURE_ATTACK:
            # Repeated invalid messages
            dummy_payload = ProtectedMessagePayload(
                nonce=self.rng.randbytes(12),
                ciphertext=self.rng.randbytes(128),
                associated_data=f"{scenario.attacker_id}->{scenario.target_id}".encode()
            )
            try:
                self.security_manager.decrypt_message(scenario.attacker_id, scenario.target_id, dummy_payload, tick)
            except Exception:
                pass
            return True, "synthetic"
            
        return False, "none"
