import pytest
import time
import json
from src.events import EventLogger
from src.security.hybrid_auth.protocol import HybridAuthProtocol
from src.security.hybrid_auth.models import AuthRequest, AuthChallenge, AuthResponse
from src.security.hybrid_auth.state import AuthState

class MockTime:
    def __init__(self):
        self.t = 1000.0
    def __call__(self):
        return self.t

def setup_protocol():
    logger = EventLogger()
    mt = MockTime()
    prot = HybridAuthProtocol(logger, challenge_ttl_seconds=30.0, time_func=mt)
    prot.register_device("devA")
    prot.register_device("devB")
    return prot, mt

# 1. Successful mutual authentication
def test_successful_mutual_authentication():
    prot, mt = setup_protocol()
    req = prot.create_request("devA", "devB")
    chal = prot.issue_challenge(req, "devB")
    resp_init = prot.respond_to_challenge(chal, "devA")
    resp_resp = prot.verify_initiator_response(resp_init, "devB")
    assert prot.verify_responder_response(resp_resp, "devA") is True
    assert prot.metrics["successful_authentications"] == 1
    assert prot.metrics["mutual_authentication_successes"] == 1

# 2. Fresh challenge generation
# 3. Different attempts receive different challenges
def test_fresh_challenge_generation():
    prot, mt = setup_protocol()
    req1 = prot.create_request("devA", "devB")
    req2 = prot.create_request("devA", "devB")
    chal1 = prot.issue_challenge(req1, "devB")
    chal2 = prot.issue_challenge(req2, "devB")
    assert chal1.challenge != chal2.challenge
    assert len(chal1.challenge) == 32

# 4. Invalid Ed25519 initiator signature
def test_invalid_initiator_ed25519():
    prot, mt = setup_protocol()
    req = prot.create_request("devA", "devB")
    chal = prot.issue_challenge(req, "devB")
    resp_init = prot.respond_to_challenge(chal, "devA")
    bad_sig = resp_init.classical_signature[:-1] + (b'\x00' if resp_init.classical_signature[-1:] != b'\x00' else b'\x01')
    resp_init.classical_signature = bad_sig
    with pytest.raises(ValueError, match="MUTUAL_AUTHENTICATION_FAILED"):
        prot.verify_initiator_response(resp_init, "devB")
    assert prot.metrics["classical_signature_failures"] == 1

# 5. Invalid ML-DSA initiator signature
def test_invalid_initiator_mldsa():
    prot, mt = setup_protocol()
    req = prot.create_request("devA", "devB")
    chal = prot.issue_challenge(req, "devB")
    resp_init = prot.respond_to_challenge(chal, "devA")
    bad_sig = resp_init.pqc_signature[:-1] + (b'\x00' if resp_init.pqc_signature[-1:] != b'\x00' else b'\x01')
    resp_init.pqc_signature = bad_sig
    with pytest.raises(ValueError, match="MUTUAL_AUTHENTICATION_FAILED"):
        prot.verify_initiator_response(resp_init, "devB")
    assert prot.metrics["pqc_signature_failures"] == 1

# 6. Invalid Ed25519 responder signature
def test_invalid_responder_ed25519():
    prot, mt = setup_protocol()
    req = prot.create_request("devA", "devB")
    chal = prot.issue_challenge(req, "devB")
    resp_init = prot.respond_to_challenge(chal, "devA")
    resp_resp = prot.verify_initiator_response(resp_init, "devB")
    
    bad_sig = resp_resp.classical_signature[:-1] + (b'\x00' if resp_resp.classical_signature[-1:] != b'\x00' else b'\x01')
    resp_resp.classical_signature = bad_sig
    with pytest.raises(ValueError, match="MUTUAL_AUTHENTICATION_FAILED"):
        prot.verify_responder_response(resp_resp, "devA")
    assert prot.metrics["classical_signature_failures"] == 1

# 7. Invalid ML-DSA responder signature
def test_invalid_responder_mldsa():
    prot, mt = setup_protocol()
    req = prot.create_request("devA", "devB")
    chal = prot.issue_challenge(req, "devB")
    resp_init = prot.respond_to_challenge(chal, "devA")
    resp_resp = prot.verify_initiator_response(resp_init, "devB")
    
    bad_sig = resp_resp.pqc_signature[:-1] + (b'\x00' if resp_resp.pqc_signature[-1:] != b'\x00' else b'\x01')
    resp_resp.pqc_signature = bad_sig
    with pytest.raises(ValueError, match="MUTUAL_AUTHENTICATION_FAILED"):
        prot.verify_responder_response(resp_resp, "devA")
    assert prot.metrics["pqc_signature_failures"] == 1

# 8. Transcript tampering
def test_transcript_tampering():
    prot, mt = setup_protocol()
    req = prot.create_request("devA", "devB")
    chal = prot.issue_challenge(req, "devB")
    resp_init = prot.respond_to_challenge(chal, "devA")
    
    resp_init.attempt_id = "fake_attempt_id"
    prot.attempts["fake_attempt_id"] = prot.attempts[req.attempt_id].copy()
    prot.attempts["fake_attempt_id"]["state"] = AuthState.CHALLENGE_ISSUED
    
    with pytest.raises(ValueError, match="MUTUAL_AUTHENTICATION_FAILED"):
        prot.verify_initiator_response(resp_init, "devB")

# 9. Initiator identity substitution
def test_initiator_identity_substitution():
    prot, mt = setup_protocol()
    prot.register_device("devC")
    req = prot.create_request("devA", "devB")
    chal = prot.issue_challenge(req, "devB")
    resp_init = prot.respond_to_challenge(chal, "devA")
    
    resp_init.initiator_id = "devC"
    with pytest.raises(ValueError, match="INVALID_IDENTITY"):
        prot.verify_initiator_response(resp_init, "devB")

# 10. Responder identity substitution
def test_responder_identity_substitution():
    prot, mt = setup_protocol()
    prot.register_device("devC")
    req = prot.create_request("devA", "devB")
    chal = prot.issue_challenge(req, "devB")
    resp_init = prot.respond_to_challenge(chal, "devA")
    
    with pytest.raises(ValueError, match="INVALID_IDENTITY"):
        prot.verify_initiator_response(resp_init, "devC")

# 11. Attempt ID tampering
def test_attempt_id_tampering():
    prot, mt = setup_protocol()
    req = prot.create_request("devA", "devB")
    chal = prot.issue_challenge(req, "devB")
    resp_init = prot.respond_to_challenge(chal, "devA")
    
    resp_init.attempt_id = "invalid_id"
    with pytest.raises(ValueError, match="INVALID_ATTEMPT"):
        prot.verify_initiator_response(resp_init, "devB")

# 12. Challenge tampering
def test_challenge_tampering():
    prot, mt = setup_protocol()
    req = prot.create_request("devA", "devB")
    chal = prot.issue_challenge(req, "devB")
    resp_init = prot.respond_to_challenge(chal, "devA")
    
    resp_init.challenge = b'\x00' * 32
    with pytest.raises(ValueError, match="UNKNOWN_CHALLENGE"):
        prot.verify_initiator_response(resp_init, "devB")

# 13. Challenge replay
def test_challenge_replay():
    prot, mt = setup_protocol()
    req = prot.create_request("devA", "devB")
    chal = prot.issue_challenge(req, "devB")
    resp_init = prot.respond_to_challenge(chal, "devA")
    resp_resp = prot.verify_initiator_response(resp_init, "devB")
    prot.verify_responder_response(resp_resp, "devA")
    
    prot.attempts[req.attempt_id]["state"] = AuthState.CHALLENGE_ISSUED
    with pytest.raises(ValueError, match="CHALLENGE_ALREADY_CONSUMED"):
        prot.verify_initiator_response(resp_init, "devB")

# 14. Cross-attempt challenge reuse
def test_cross_attempt_challenge():
    prot, mt = setup_protocol()
    reqA = prot.create_request("devA", "devB")
    chalA = prot.issue_challenge(reqA, "devB")
    
    reqB = prot.create_request("devA", "devB")
    chalB = prot.issue_challenge(reqB, "devB")
    
    resp_init = prot.respond_to_challenge(chalA, "devA")
    resp_init.attempt_id = reqB.attempt_id
    
    with pytest.raises(ValueError, match="UNKNOWN_CHALLENGE"):
        prot.verify_initiator_response(resp_init, "devB")

# 15. Expired challenge
def test_expired_challenge():
    prot, mt = setup_protocol()
    req = prot.create_request("devA", "devB")
    chal = prot.issue_challenge(req, "devB")
    resp_init = prot.respond_to_challenge(chal, "devA")
    mt.t += 35.0
    with pytest.raises(ValueError, match="EXPIRED_CHALLENGE"):
        prot.verify_initiator_response(resp_init, "devB")

# 16. Unknown challenge
def test_unknown_challenge():
    prot, mt = setup_protocol()
    req = prot.create_request("devA", "devB")
    chal = prot.issue_challenge(req, "devB")
    chal.challenge = b"not_the_right_challenge123456789"
    with pytest.raises(ValueError, match="UNKNOWN_CHALLENGE"):
        prot.respond_to_challenge(chal, "devA")

# 17. Invalid state transition
def test_invalid_state_transition():
    prot, mt = setup_protocol()
    req = prot.create_request("devA", "devB")
    chal = AuthChallenge(req.attempt_id, b'0'*32, "devB")
    with pytest.raises(ValueError, match="INVALID_STATE"):
        prot.respond_to_challenge(chal, "devA")

# 18. Authentication event generation
def test_authentication_events():
    prot, mt = setup_protocol()
    req = prot.create_request("devA", "devB")
    chal = prot.issue_challenge(req, "devB")
    resp_init = prot.respond_to_challenge(chal, "devA")
    resp_resp = prot.verify_initiator_response(resp_init, "devB")
    prot.verify_responder_response(resp_resp, "devA")
    
    events = [e["event_type"] for e in prot.logger.get_events()]
    assert "HYBRID_AUTH_REQUESTED" in events
    assert "HYBRID_AUTH_CHALLENGE_ISSUED" in events
    assert "HYBRID_AUTH_RESPONSE_RECEIVED" in events
    assert "HYBRID_AUTH_VERIFICATION_SUCCESS" in events

# 19. Authentication metric correctness
# 20. Authentication latency measurement
def test_authentication_metrics_and_latency():
    prot, mt = setup_protocol()
    req = prot.create_request("devA", "devB")
    chal = prot.issue_challenge(req, "devB")
    resp_init = prot.respond_to_challenge(chal, "devA")
    resp_resp = prot.verify_initiator_response(resp_init, "devB")
    prot.verify_responder_response(resp_resp, "devA")
    
    assert prot.metrics["authentication_attempts"] == 1
    assert prot.metrics["successful_authentications"] == 1
    assert prot.metrics["failed_authentications"] == 0
    assert prot.metrics["authentication_latency"] > 0

# 21. No session-key derivation
def test_no_session_key_derivation():
    prot, mt = setup_protocol()
    import inspect
    methods = [name for name, _ in inspect.getmembers(prot, predicate=inspect.ismethod)]
    for m in methods:
        assert "derive" not in m.lower()
        assert "session_key" not in m.lower()

# 22. No secret material in logs
def test_no_secrets_in_logs():
    prot, mt = setup_protocol()
    req = prot.create_request("devA", "devB")
    chal = prot.issue_challenge(req, "devB")
    resp_init = prot.respond_to_challenge(chal, "devA")
    resp_resp = prot.verify_initiator_response(resp_init, "devB")
    prot.verify_responder_response(resp_resp, "devA")
    
    log_str = json.dumps(prot.logger.get_events())
    assert chal.challenge.hex() not in log_str
    assert "private" not in log_str.lower()
    assert "secret" not in log_str.lower()

# 23. Fresh challenge after a failed authentication
def test_fresh_challenge_after_fail():
    prot, mt = setup_protocol()
    req = prot.create_request("devA", "devB")
    chal = prot.issue_challenge(req, "devB")
    
    prot.attempts[req.attempt_id]["state"] = AuthState.AUTHENTICATION_FAILED
    
    req2 = prot.create_request("devA", "devB")
    chal2 = prot.issue_challenge(req2, "devB")
    assert chal.challenge != chal2.challenge

# 24. Challenge remains usable after responder-proof failure
# 25. Challenge becomes unusable after successful mutual authentication
def test_critical_challenge_lifecycle():
    prot, mt = setup_protocol()
    req = prot.create_request("devA", "devB")
    chal = prot.issue_challenge(req, "devB")
    resp_init = prot.respond_to_challenge(chal, "devA")
    resp_resp = prot.verify_initiator_response(resp_init, "devB")
    
    resp_resp.classical_signature = resp_resp.classical_signature[:-1] + (b'\x00' if resp_resp.classical_signature[-1:] != b'\x00' else b'\x01')
    
    with pytest.raises(ValueError, match="MUTUAL_AUTHENTICATION_FAILED"):
        prot.verify_responder_response(resp_resp, "devA")
        
    assert chal.challenge not in prot.consumed_challenges
    
    # Retry legitimate proof (simulate valid retry on same attempt_id)
    prot.attempts[req.attempt_id]["state"] = AuthState.RESPONSE_RECEIVED
    resp_resp2 = prot.verify_initiator_response(resp_init, "devB") 
    
    res = prot.verify_responder_response(resp_resp2, "devA")
    assert res is True
    
    assert chal.challenge in prot.consumed_challenges
    
    prot.attempts[req.attempt_id]["state"] = AuthState.CHALLENGE_ISSUED
    with pytest.raises(ValueError, match="CHALLENGE_ALREADY_CONSUMED"):
        prot.verify_initiator_response(resp_init, "devB")
