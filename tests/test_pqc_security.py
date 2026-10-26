import pytest
from src.events import EventLogger, EventType
from src.security.pqc.manager import PQCSecurityManager
from src.security.pqc.keys import PQCIdentityKey, PQCEphemeralKey
from src.security.pqc.authentication import PQCAuthenticator
from src.security.pqc.key_exchange import PQCKeyExchange
from src.security.manager import ProtectedMessagePayload
import secrets
import json

def test_pqc_ml_dsa_signatures():
    # 1. ML-DSA key generation
    ik = PQCIdentityKey()
    assert ik.public_key is not None
    assert ik.private_key is not None
    
    # 2. ML-DSA valid signature
    msg = b"test message"
    sig = PQCAuthenticator.sign(ik.private_key, msg)
    assert PQCAuthenticator.verify(ik.public_key, sig, msg) is True
    
    # 3. ML-DSA invalid signature
    bad_sig = bytearray(sig)
    bad_sig[0] ^= 0xFF
    assert PQCAuthenticator.verify(ik.public_key, bytes(bad_sig), msg) is False

def test_pqc_authentication_freshness_and_integrity():
    logger = EventLogger()
    sm = PQCSecurityManager(logger)
    sm.register_device("devA")
    sm.register_device("devB")
    
    ik_a = sm.my_identities["devA"]
    
    # 4. Fresh authentication challenge (manual test of transcript logic)
    challenge = secrets.token_bytes(32)
    # 5. Authentication transcript integrity
    transcript = b"PQC-AUTH|" + b"devA" + b"|" + b"devB" + b"|" + challenge
    sig_a = PQCAuthenticator.sign(ik_a.private_key, transcript)
    assert PQCAuthenticator.verify(sm.identities["devA"], sig_a, transcript) is True
    
    # 6. Modified challenge rejection
    bad_transcript1 = b"PQC-AUTH|" + b"devA" + b"|" + b"devB" + b"|" + secrets.token_bytes(32)
    assert PQCAuthenticator.verify(sm.identities["devA"], sig_a, bad_transcript1) is False
    
    # 7. Modified identity rejection
    bad_transcript2 = b"PQC-AUTH|" + b"devX" + b"|" + b"devB" + b"|" + challenge
    assert PQCAuthenticator.verify(sm.identities["devA"], sig_a, bad_transcript2) is False

def test_pqc_unknown_identity_rejection():
    # 8. Unknown identity rejection & 18. Failed authentication prevents session establishment
    logger = EventLogger()
    sm = PQCSecurityManager(logger)
    sm.register_device("devA")
    # devB is not registered
    assert sm.authenticate_and_exchange("devA", "devB", 1) is False
    assert ("devA", "devB") not in sm.sessions

def test_pqc_ml_kem_key_establishment():
    # 9. ML-KEM key generation
    ek = PQCEphemeralKey()
    assert ek.public_key is not None
    assert ek.private_key is not None
    
    # 10. ML-KEM encapsulation/decapsulation
    shared_secret, ct = PQCKeyExchange.encapsulate(ek.public_key)
    # 11. Shared-secret equality
    dec_shared = PQCKeyExchange.decapsulate(ek.private_key, ct)
    assert shared_secret == dec_shared
    
    # 12. HKDF session-key equality
    sk1 = PQCKeyExchange.derive_session_key(shared_secret)
    sk2 = PQCKeyExchange.derive_session_key(dec_shared)
    assert sk1 == sk2
    assert len(sk1) == 32

def test_pqc_aes_gcm_payload_protection():
    logger = EventLogger()
    sm = PQCSecurityManager(logger)
    sm.register_device("devA")
    sm.register_device("devB")
    
    # 19. Successful PQC session establishment
    assert sm.authenticate_and_exchange("devA", "devB", 1) is True
    
    # 13. AES-GCM encryption/decryption
    payload = sm.encrypt_message("devA", "devB", {"msg": "hello"}, 2)
    dec = sm.decrypt_message("devA", "devB", payload, 3)
    assert dec["msg"] == "hello"
    
    # 14. Ciphertext tampering rejection
    bad_ct = bytearray(payload.ciphertext)
    bad_ct[0] ^= 0xFF
    bad_payload = ProtectedMessagePayload(payload.nonce, bytes(bad_ct), payload.associated_data)
    with pytest.raises(ValueError):
        sm.decrypt_message("devA", "devB", bad_payload, 4)
        
    # 15. Associated-data tampering rejection
    bad_payload_ad = ProtectedMessagePayload(payload.nonce, payload.ciphertext, b"bad_ad")
    with pytest.raises(ValueError):
        sm.decrypt_message("devA", "devB", bad_payload_ad, 5)

def test_pqc_strict_session_scoped_replay_protection():
    logger = EventLogger()
    sm = PQCSecurityManager(logger)
    sm.register_device("devA")
    sm.register_device("devB")
    
    # Establish Session 1
    sm.authenticate_and_exchange("devA", "devB", 1)
    session_id_1, _ = sm.sessions[("devA", "devB")]
    
    # Test A: Same nonce + same sender + same receiver + same session -> second use rejected
    payload_1 = sm.encrypt_message("devA", "devB", {"msg": "hello"}, 2)
    nonce = payload_1.nonce
    
    # First time works
    sm.decrypt_message("devA", "devB", payload_1, 3)
    
    # Second time rejects (TEST A)
    with pytest.raises(ValueError, match="Replay detected"):
        sm.decrypt_message("devA", "devB", payload_1, 4)
        
    # Check TEST E: Replay detection produces structured event
    events = logger.get_events()
    replay_events = [e for e in events if e["event_type"] == EventType.REPLAY_DETECTED.value]
    assert len(replay_events) == 1
    assert replay_events[0]["details"]["sender"] == "devA"
    assert replay_events[0]["details"]["receiver"] == "devB"
    assert replay_events[0]["details"]["security_mode"] == "PQC"
    
    # Establish Session 2 (forces a new session ID)
    sm.authenticate_and_exchange("devA", "devB", 5)
    session_id_2, session_key_2 = sm.sessions[("devA", "devB")]
    assert session_id_1 != session_id_2
    
    # Test B & C: Same nonce + same sender/receiver + DIFFERENT session -> accepted
    # We craft a message for Session 2 using the SAME nonce as Session 1.
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aes = AESGCM(session_key_2)
    ad = f"devA->devB|PQC|{session_id_2}".encode()
    ct = aes.encrypt(nonce, b'{"msg": "hi"}', ad)
    
    payload_2 = ProtectedMessagePayload(nonce, ct, ad, session_id_2)
    
    # This must succeed without raising Replay detected
    dec = sm.decrypt_message("devA", "devB", payload_2, 6)
    assert dec["msg"] == "hi"

    # Test D: Wrong/unknown session identifier is rejected safely
    bad_payload = ProtectedMessagePayload(nonce, ct, ad, "invalid_session_id_123")
    with pytest.raises(ValueError, match="Session ID mismatch"):
        sm.decrypt_message("devA", "devB", bad_payload, 7)

def test_pqc_replay_prevented_before_processing():
    # TEST F: Replay is rejected before processed
    logger = EventLogger()
    sm = PQCSecurityManager(logger)
    sm.register_device("devA")
    sm.register_device("devB")
    sm.authenticate_and_exchange("devA", "devB", 1)
    
    payload = sm.encrypt_message("devA", "devB", {"msg": "payload"}, 2)
    
    # Process once successfully
    sm.decrypt_message("devA", "devB", payload, 3)
    
    # Attempting to decrypt it again raises Replay Detected immediately, 
    # preventing the plaintext from ever being accessed/returned.
    with pytest.raises(ValueError, match="Replay detected"):
        sm.decrypt_message("devA", "devB", payload, 4)

def test_pqc_forged_ciphertext_does_not_poison_replay_cache():
    logger = EventLogger()
    sm = PQCSecurityManager(logger)
    sm.register_device("devA")
    sm.register_device("devB")
    sm.authenticate_and_exchange("devA", "devB", 1)
    
    session_id, session_key = sm.sessions[("devA", "devB")]
    
    # Create a fresh nonce X
    nonce_x = secrets.token_bytes(12)
    
    # TEST 2: Forged ciphertext with fresh nonce X
    # AES-GCM authentication fails.
    bad_ct = b"invalid_ciphertext_that_is_long_enough_to_have_tag" * 2
    bad_ad = f"devA->devB|PQC|{session_id}".encode()
    
    forged_payload = ProtectedMessagePayload(nonce_x, bad_ct, bad_ad, session_id)
    
    # The decryption MUST fail due to integrity verification
    with pytest.raises(ValueError): # Expected: cryptography InvalidTag or AESGCM decrypt ValueError
        sm.decrypt_message("devA", "devB", forged_payload, 2)
        
    # Verify the event log for integrity failure
    events = logger.get_events()
    assert any(e["event_type"] == EventType.INTEGRITY_VERIFICATION_FAILED.value for e in events)
    
    # The crucial part: Nonce X must NOT become permanently recorded as a replay.
    # We prove this by constructing a valid message using the SAME nonce X.
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aes = AESGCM(session_key)
    valid_ct_x = aes.encrypt(nonce_x, b'{"msg": "valid_after_forge"}', bad_ad)
    valid_payload_x = ProtectedMessagePayload(nonce_x, valid_ct_x, bad_ad, session_id)
    
    # If the replay cache was poisoned, this would raise "Replay detected"
    # But because it wasn't, this decrypts successfully!
    dec = sm.decrypt_message("devA", "devB", valid_payload_x, 3)
    assert dec["msg"] == "valid_after_forge"
    
    # TEST 3: Construct a valid authenticated message using a fresh valid nonce Y
    nonce_y = secrets.token_bytes(12)
    valid_ct_y = aes.encrypt(nonce_y, b'{"msg": "valid_y"}', bad_ad)
    valid_payload_y = ProtectedMessagePayload(nonce_y, valid_ct_y, bad_ad, session_id)
    
    dec_y = sm.decrypt_message("devA", "devB", valid_payload_y, 4)
    assert dec_y["msg"] == "valid_y"

def test_pqc_events_and_secrets():
    # 20. Security event generation & 21. No PQC secret material in logs
    logger = EventLogger()
    sm = PQCSecurityManager(logger)
    sm.register_device("devA")
    sm.register_device("devB")
    sm.authenticate_and_exchange("devA", "devB", 1)
    
    events = logger.get_events()
    assert len(events) > 0
    log_str = json.dumps(events)
    assert "PQC" in log_str
    
    # We shouldn't see any massive base64 keys or session keys in logs
    # E.g. ML-DSA private key is around 4K bytes, ML-KEM shared secret is 32 bytes
    assert "private_key" not in log_str.lower()
    assert "session_key" not in log_str.lower()

def test_pqc_experiment_executes():
    # 22. PQC experiment executes & 23. Protected PQC messages use the real Step 2 network
    import os
    import subprocess
    import sys
    env = {**os.environ, "PYTHONPATH": "."}
    result = subprocess.run([sys.executable, "experiments/pqc_security_baseline.py"], capture_output=True, text=True, env=env)
    assert result.returncode == 0
    assert "PQC Security Baseline Simulation" in result.stdout
    assert "Authentication Failures: 0" in result.stdout
