import pytest
from src.security.attacker import (
    AttackScenario, AttackType, AttackIntensity, AttackerProfile, 
    AttackerSimulator, AttackScheduler
)
from src.events import EventLogger, EventType
from src.security.manager import SecurityManager, ProtectedMessagePayload

def test_attack_scenario_validation():
    # Negative start tick
    with pytest.raises(ValueError, match="start_tick cannot be negative"):
        AttackScenario("a1", AttackType.AUTHENTICATION_ATTACK, "atk", "tgt", "ctx", -1, 5, AttackIntensity.LOW)
        
    # Negative duration
    with pytest.raises(ValueError, match="duration_ticks cannot be negative"):
        AttackScenario("a1", AttackType.AUTHENTICATION_ATTACK, "atk", "tgt", "ctx", 0, -5, AttackIntensity.LOW)
        
    # attacker == target
    with pytest.raises(ValueError, match="attacker_id cannot be the same as target_id"):
        AttackScenario("a1", AttackType.AUTHENTICATION_ATTACK, "atk", "atk", "ctx", 0, 5, AttackIntensity.LOW)
        
    # Invalid type
    with pytest.raises(ValueError, match="Invalid attack_type"):
        AttackScenario("a1", "NOT_AN_ENUM", "atk", "tgt", "ctx", 0, 5, AttackIntensity.LOW)
        
    # Invalid intensity
    with pytest.raises(ValueError, match="Invalid intensity"):
        AttackScenario("a1", AttackType.AUTHENTICATION_ATTACK, "atk", "tgt", "ctx", 0, 5, "LOW")

def test_scheduler_validation():
    sched = AttackScheduler()
    prof = AttackerProfile("atk", [AttackType.AUTHENTICATION_ATTACK], AttackIntensity.HIGH)
    sched.register_attacker(prof)
    sched.update_environment(["tgt"], ["ctx"])
    
    # Unknown attacker
    scen1 = AttackScenario("a1", AttackType.AUTHENTICATION_ATTACK, "unknown_atk", "tgt", "ctx", 0, 5, AttackIntensity.LOW)
    with pytest.raises(ValueError, match="Unknown attacker"):
        sched.schedule_attack(scen1)
        
    # Capability mismatch
    scen2 = AttackScenario("a1", AttackType.REPLAY_ATTACK, "atk", "tgt", "ctx", 0, 5, AttackIntensity.LOW)
    with pytest.raises(ValueError, match="cannot perform"):
        sched.schedule_attack(scen2)
        
    # Unknown target
    scen3 = AttackScenario("a1", AttackType.AUTHENTICATION_ATTACK, "atk", "unknown_tgt", "ctx", 0, 5, AttackIntensity.LOW)
    with pytest.raises(ValueError, match="Unknown target entity"):
        sched.schedule_attack(scen3)
        
    # Unknown context
    scen4 = AttackScenario("a1", AttackType.AUTHENTICATION_ATTACK, "atk", "tgt", "unknown_ctx", 0, 5, AttackIntensity.LOW)
    with pytest.raises(ValueError, match="Unknown context"):
        sched.schedule_attack(scen4)

def test_deterministic_scheduling_and_overlap():
    sched = AttackScheduler()
    prof = AttackerProfile("atk", [AttackType.AUTHENTICATION_ATTACK], AttackIntensity.HIGH)
    sched.register_attacker(prof)
    sched.update_environment(["tgt1", "tgt2"], ["ctx1", "ctx2"])
    
    s1 = AttackScenario("a1", AttackType.AUTHENTICATION_ATTACK, "atk", "tgt1", "ctx1", 10, 5, AttackIntensity.LOW)
    s2 = AttackScenario("a2", AttackType.AUTHENTICATION_ATTACK, "atk", "tgt2", "ctx2", 12, 5, AttackIntensity.LOW)
    s3 = AttackScenario("a3", AttackType.AUTHENTICATION_ATTACK, "atk", "tgt1", "ctx2", 12, 1, AttackIntensity.LOW)
    
    sched.schedule_attack(s2)
    sched.schedule_attack(s1)
    sched.schedule_attack(s3)
    
    assert sched.scenarios[0].attack_id == "a1"
    assert sched.scenarios[1].attack_id == "a2" or sched.scenarios[1].attack_id == "a3"
    
    # Tick 12 should have all 3 attacks
    attacks = sched.get_attacks_for_tick(12)
    assert len(attacks) == 3

def test_authentication_attack():
    logger = EventLogger()
    sm = SecurityManager(logger)
    sm.register_device("tgt")
    sim = AttackerSimulator(sm, logger)
    sim.set_environment(["tgt"], ["ctx"])
    prof = AttackerProfile("atk", [AttackType.AUTHENTICATION_ATTACK], AttackIntensity.LOW)
    sim.scheduler.register_attacker(prof)
    
    s1 = AttackScenario("a1", AttackType.AUTHENTICATION_ATTACK, "atk", "tgt", "ctx", 1, 1, AttackIntensity.LOW)
    sim.schedule_attack(s1)
    
    sim.process_tick(1)
    sim.process_tick(2)
    
    # Ground truth check
    gt = sim.ground_truths["a1"]
    assert gt.attack_scheduled
    assert gt.attack_attempted
    assert gt.attack_injected
    assert gt.events_generated == 2 # 1 per tick
    
    # Should see authentication failures
    auth_fails = [e for e in logger.get_events() if e["event_type"] == EventType.AUTHENTICATION_FAILURE.value]
    assert len(auth_fails) == 2
    
def test_replay_attack():
    logger = EventLogger()
    sm = SecurityManager(logger)
    sm.register_device("tgt")
    sim = AttackerSimulator(sm, logger)
    sim.set_environment(["tgt"], ["ctx"])
    prof = AttackerProfile("atk", [AttackType.REPLAY_ATTACK], AttackIntensity.LOW)
    sim.scheduler.register_attacker(prof)
    
    s1 = AttackScenario("a1", AttackType.REPLAY_ATTACK, "atk", "tgt", "ctx", 1, 0, AttackIntensity.LOW)
    sim.schedule_attack(s1)
    sim.process_tick(1)
    
    gt = sim.ground_truths["a1"]
    assert gt.attack_injected
    
def test_tampering_attack():
    logger = EventLogger()
    sm = SecurityManager(logger)
    sm.register_device("tgt")
    sim = AttackerSimulator(sm, logger)
    sim.set_environment(["tgt"], ["ctx"])
    prof = AttackerProfile("atk", [AttackType.MESSAGE_TAMPERING_ATTACK], AttackIntensity.LOW)
    sim.scheduler.register_attacker(prof)
    
    s1 = AttackScenario("a1", AttackType.MESSAGE_TAMPERING_ATTACK, "atk", "tgt", "ctx", 1, 0, AttackIntensity.LOW)
    sim.schedule_attack(s1)
    sim.process_tick(1)
    assert sim.ground_truths["a1"].attack_injected
    
def test_session_abuse_and_resource_pressure():
    logger = EventLogger()
    sm = SecurityManager(logger)
    sm.register_device("tgt")
    sim = AttackerSimulator(sm, logger)
    sim.set_environment(["tgt"], ["ctx"])
    prof = AttackerProfile("atk", [AttackType.SESSION_ABUSE_ATTACK, AttackType.RESOURCE_PRESSURE_ATTACK], AttackIntensity.HIGH)
    sim.scheduler.register_attacker(prof)
    
    s1 = AttackScenario("a1", AttackType.SESSION_ABUSE_ATTACK, "atk", "tgt", "ctx", 1, 0, AttackIntensity.HIGH)
    s2 = AttackScenario("a2", AttackType.RESOURCE_PRESSURE_ATTACK, "atk", "tgt", "ctx", 1, 0, AttackIntensity.HIGH)
    sim.schedule_attack(s1)
    sim.schedule_attack(s2)
    sim.process_tick(1)
    
    # HIGH intensity = 20 attempts
    assert sim.ground_truths["a1"].events_generated == 20
    assert sim.ground_truths["a2"].events_generated == 20

def test_event_structure_and_no_secrets():
    logger = EventLogger()
    sm = SecurityManager(logger)
    sm.register_device("tgt")
    sim = AttackerSimulator(sm, logger)
    sim.set_environment(["tgt"], ["ctx"])
    prof = AttackerProfile("atk", [AttackType.AUTHENTICATION_ATTACK], AttackIntensity.LOW)
    sim.scheduler.register_attacker(prof)
    
    s1 = AttackScenario("a1", AttackType.AUTHENTICATION_ATTACK, "atk", "tgt", "ctx", 1, 0, AttackIntensity.LOW)
    sim.schedule_attack(s1)
    sim.process_tick(1)
    
    events = logger.get_events()
    attack_events = [e for e in events if e["event_type"] in [
        EventType.ATTACK_SCHEDULED.value, 
        EventType.ATTACK_STARTED.value, 
        EventType.ATTACK_ATTEMPTED.value, 
        EventType.ATTACK_INJECTED.value, 
        EventType.ATTACK_COMPLETED.value
    ]]
    
    assert len(attack_events) == 5
    for e in attack_events:
        details = str(e["details"])
        assert "private_key" not in details
        assert "secret" not in details
        
def test_coordinated_attack():
    logger = EventLogger()
    sm = SecurityManager(logger)
    sm.register_device("tgt")
    sim = AttackerSimulator(sm, logger)
    sim.set_environment(["tgt"], ["ctx"])
    prof = AttackerProfile("atk", [AttackType.COORDINATED_ATTACK, AttackType.AUTHENTICATION_ATTACK, AttackType.REPLAY_ATTACK], AttackIntensity.LOW)
    sim.scheduler.register_attacker(prof)
    
    s1 = AttackScenario("sub1", AttackType.AUTHENTICATION_ATTACK, "atk", "tgt", "ctx", 1, 0, AttackIntensity.LOW)
    s2 = AttackScenario("sub2", AttackType.REPLAY_ATTACK, "atk", "tgt", "ctx", 1, 0, AttackIntensity.LOW)
    
    coord = AttackScenario("coord1", AttackType.COORDINATED_ATTACK, "atk", "tgt", "ctx", 1, 0, AttackIntensity.LOW, sub_scenarios=[s1, s2])
    
    sim.schedule_attack(coord)
    sim.process_tick(1)
    
    gt = sim.ground_truths["coord1"]
    assert gt.attack_injected
    assert gt.events_generated == 2 # 1 per sub-scenario for LOW intensity
    
def test_reproducibility():
    def run_sim(seed):
        logger = EventLogger()
        sm = SecurityManager(logger)
        sm.register_device("tgt")
        sim = AttackerSimulator(sm, logger, seed=seed)
        sim.set_environment(["tgt"], ["ctx"])
        prof = AttackerProfile("atk", [AttackType.MESSAGE_TAMPERING_ATTACK], AttackIntensity.LOW)
        sim.scheduler.register_attacker(prof)
        s1 = AttackScenario("a1", AttackType.MESSAGE_TAMPERING_ATTACK, "atk", "tgt", "ctx", 1, 0, AttackIntensity.LOW)
        sim.schedule_attack(s1)
        sim.process_tick(1)
        return logger.get_events(), sim.ground_truths["a1"].to_dict()
        
    events1, gt1 = run_sim(42)
    events2, gt2 = run_sim(42)
    events3, gt3 = run_sim(99)
    
    assert events1 == events2
    assert gt1 == gt2
    
    # Event timestamps and sequence should be identical for same seed
