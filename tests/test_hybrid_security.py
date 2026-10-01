import pytest
import secrets
import json

from src.events import EventLogger, EventType
from src.security.hybrid.manager import HybridSecurityManager
from src.security.hybrid.keys import HybridIdentityKey, HybridEphemeralKey
from src.security.hybrid.key_exchange import HybridKeyExchange
from src.security.manager import ProtectedMessagePayload

def test_hybrid_keys_and_components():
    ik = HybridIdentityKey()
    assert ik.classical.public_key is not None
    assert ik.pqc.public_key is not None

    ek = HybridEphemeralKey()
    assert ek.classical.public_key is not None
    assert ek.pqc.public_key is not None

def test_hybrid_auth_and_kx():
    logger = EventLogger()
    sm = HybridSecurityManager(logger)
    sm.register_device("devA")
    sm.register_device("devB")

    # Success case
    assert sm.authenticate_and_exchange("devA", "devB", 1) is True
    
    # Assert session is established
    assert ("devA", "devB") in sm.sessions
    
    session_id, session_key = sm.sessions[("devA", "devB")]
    assert len(session_key) == 32

def test_hybrid_kdf_contributions():
    # Prove that BOTH classical and PQC secrets contribute
    ss_class_1 = secrets.token_bytes(32)
    ss_pqc_1 = secrets.token_bytes(32)
    
    key1 = HybridKeyExchange.derive_session_key(ss_class_1, ss_pqc_1)
    
    # Change classical
    ss_class_2 = secrets.token_bytes(32)
    key2 = HybridKeyExchange.derive_session_key(ss_class_2, ss_pqc_1)
    assert key1 != key2
    
    # Change PQC
    ss_pqc_2 = secrets.token_bytes(32)
    key3 = HybridKeyExchange.derive_session_key(ss_class_1, ss_pqc_2)
    assert key1 != key3

def test_hybrid_encryption_and_tampering():
    logger = EventLogger()
    sm = HybridSecurityManager(logger)
    sm.register_device("devA")
    sm.register_device("devB")
    sm.authenticate_and_exchange("devA", "devB", 1)
    
    payload = {"msg": "hello hybrid"}
    protected = sm.encrypt_message("devA", "devB", payload, 2)
    
    # Success decrypt
    dec = sm.decrypt_message("devA", "devB", protected, 3)
    assert dec["msg"] == "hello hybrid"
    
    # Tampered ciphertext
    protected_tampered_ct = ProtectedMessagePayload(
        nonce=protected.nonce,
        ciphertext=protected.ciphertext[:-1] + (b'\x00' if protected.ciphertext[-1:] != b'\x00' else b'\x01'),
        associated_data=protected.associated_data,
        session_id=protected.session_id
    )
    with pytest.raises(ValueError):
        sm.decrypt_message("devA", "devB", protected_tampered_ct, 4)
        
    # Tampered AAD
    protected_tampered_aad = ProtectedMessagePayload(
        nonce=protected.nonce,
        ciphertext=protected.ciphertext,
        associated_data=protected.associated_data + b'X',
        session_id=protected.session_id
    )
    with pytest.raises(ValueError):
        sm.decrypt_message("devA", "devB", protected_tampered_aad, 5)

def test_hybrid_wrong_session_id():
    logger = EventLogger()
    sm = HybridSecurityManager(logger)
    sm.register_device("devA")
    sm.register_device("devB")
    sm.authenticate_and_exchange("devA", "devB", 1)
    
    protected = sm.encrypt_message("devA", "devB", {"msg": "hi"}, 2)
    protected.session_id = "wrong_session"
    
    with pytest.raises(ValueError, match="Session ID mismatch"):
        sm.decrypt_message("devA", "devB", protected, 3)

def test_hybrid_replay_protection():
    logger = EventLogger()
    sm = HybridSecurityManager(logger)
    sm.register_device("devA")
    sm.register_device("devB")
    sm.authenticate_and_exchange("devA", "devB", 1)
    
    protected = sm.encrypt_message("devA", "devB", {"msg": "hi"}, 2)
    nonce = protected.nonce
    
    # First time works
    sm.decrypt_message("devA", "devB", protected, 3)
    
    # Second time rejects
    with pytest.raises(ValueError, match="Replay detected"):
        sm.decrypt_message("devA", "devB", protected, 4)
        
    # Same nonce in a different session
    sm.authenticate_and_exchange("devA", "devB", 5) # establish new session
    session_id_2, session_key_2 = sm.sessions[("devA", "devB")]
    
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aes = AESGCM(session_key_2)
    aad = f"devA->devB|HYBRID|{session_id_2}".encode()
    ct = aes.encrypt(nonce, b'{"msg": "new session"}', aad)
    protected_2 = ProtectedMessagePayload(nonce, ct, aad, session_id_2)
    
    # Works because replay is session-scoped
    dec = sm.decrypt_message("devA", "devB", protected_2, 6)
    assert dec["msg"] == "new session"

def test_hybrid_forged_ciphertext_does_not_poison_replay_cache():
    logger = EventLogger()
    sm = HybridSecurityManager(logger)
    sm.register_device("devA")
    sm.register_device("devB")
    sm.authenticate_and_exchange("devA", "devB", 1)
    
    session_id, session_key = sm.sessions[("devA", "devB")]
    nonce_x = secrets.token_bytes(12)
    
    bad_ct = b"invalid_ciphertext_that_is_long_enough_to_have_tag" * 2
    bad_ad = f"devA->devB|HYBRID|{session_id}".encode()
    
    forged = ProtectedMessagePayload(nonce_x, bad_ct, bad_ad, session_id)
    with pytest.raises(ValueError):
        sm.decrypt_message("devA", "devB", forged, 2)
        
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aes = AESGCM(session_key)
    valid_ct = aes.encrypt(nonce_x, b'{"msg": "real"}', bad_ad)
    valid_payload = ProtectedMessagePayload(nonce_x, valid_ct, bad_ad, session_id)
    
    dec = sm.decrypt_message("devA", "devB", valid_payload, 3)
    assert dec["msg"] == "real"

import unittest.mock
from src.security.hybrid.authentication import HybridAuthenticator

def test_hybrid_invalid_classical_signature():
    ik_init = HybridIdentityKey()
    message = b"TEST_TRANSCRIPT"
    sig_classical, sig_pqc = HybridAuthenticator.sign(ik_init.classical.private_key, ik_init.pqc.private_key, message)
    
    # Tamper classical signature
    bad_sig_classical = sig_classical[:-1] + (b'\x00' if sig_classical[-1:] != b'\x00' else b'\x01')
    
    valid = HybridAuthenticator.verify(ik_init.classical.public_key, ik_init.pqc.public_key, (bad_sig_classical, sig_pqc), message)
    assert valid is False

def test_hybrid_invalid_pqc_signature():
    ik_init = HybridIdentityKey()
    message = b"TEST_TRANSCRIPT"
    sig_classical, sig_pqc = HybridAuthenticator.sign(ik_init.classical.private_key, ik_init.pqc.private_key, message)
    
    # Tamper PQC signature
    bad_sig_pqc = sig_pqc[:-1] + (b'\x00' if sig_pqc[-1:] != b'\x00' else b'\x01')
    
    valid = HybridAuthenticator.verify(ik_init.classical.public_key, ik_init.pqc.public_key, (sig_classical, bad_sig_pqc), message)
    assert valid is False

def test_hybrid_transcript_tampering():
    ik_init = HybridIdentityKey()
    message = b"TEST_TRANSCRIPT"
    sig_classical, sig_pqc = HybridAuthenticator.sign(ik_init.classical.private_key, ik_init.pqc.private_key, message)
    
    # Tamper message/transcript
    bad_message = b"TAMPERED_TRANSCRIPT"
    
    valid = HybridAuthenticator.verify(ik_init.classical.public_key, ik_init.pqc.public_key, (sig_classical, sig_pqc), bad_message)
    assert valid is False

def test_hybrid_fresh_challenge():
    logger = EventLogger()
    sm = HybridSecurityManager(logger)
    sm.register_device("devA")
    sm.register_device("devB")

    generated_challenges = set()
    original_token_bytes = secrets.token_bytes
    
    def mock_token_bytes(nbytes=None):
        val = original_token_bytes(nbytes)
        generated_challenges.add(val)
        return val

    with unittest.mock.patch('secrets.token_bytes', side_effect=mock_token_bytes):
        sm.authenticate_and_exchange("devA", "devB", 1)
        sm.authenticate_and_exchange("devA", "devB", 2)
        
    # Prove that token_bytes generated different distinct challenges for each attempt
    assert len(generated_challenges) >= 2
