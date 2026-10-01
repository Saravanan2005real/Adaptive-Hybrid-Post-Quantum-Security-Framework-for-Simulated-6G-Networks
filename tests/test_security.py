import pytest
import os
import copy
from src.security.keys import IdentityKey, EphemeralKey
from src.security.authentication import Authenticator
from src.security.key_exchange import KeyExchange
from src.security.encryption import AESGCMEncryption
from src.security.replay import ReplayProtector
from src.security.manager import SecurityManager, ProtectedMessagePayload
from src.events import EventLogger, EventType

def test_classical_key_generation():
    ik = IdentityKey()
    assert ik.private_key is not None
    assert ik.public_key is not None
    
    ek = EphemeralKey()
    assert ek.private_key is not None
    assert ek.public_key is not None

def test_ed25519_signatures():
    ik = IdentityKey()
    data = b"test_data"
    
    # Sign
    sig = Authenticator.sign(ik.private_key, data)
    assert len(sig) > 0
    
    # Verify
    assert Authenticator.verify(ik.public_key, sig, data) is True
    
    # Invalid verify
    assert Authenticator.verify(ik.public_key, sig, b"wrong_data") is False
    bad_sig = bytearray(sig)
    bad_sig[0] ^= 1
    assert Authenticator.verify(ik.public_key, bytes(bad_sig), data) is False

def test_x25519_and_hkdf():
    ek1 = EphemeralKey()
    ek2 = EphemeralKey()
    
    ss1 = KeyExchange.derive_shared_secret(ek1.private_key, ek2.public_key)
    ss2 = KeyExchange.derive_shared_secret(ek2.private_key, ek1.public_key)
    
    assert ss1 == ss2
    
    sess1 = KeyExchange.derive_session_key(ss1)
    sess2 = KeyExchange.derive_session_key(ss2)
    
    assert sess1 == sess2
    assert len(sess1) == 32

def test_aesgcm_encryption_tampering():
    key = os.urandom(32)
    pt = b"secret_message"
    ad = b"header_info"
    
    nonce, ct = AESGCMEncryption.encrypt(key, pt, ad)
    
    # Decrypt
    dec = AESGCMEncryption.decrypt(key, nonce, ct, ad)
    assert dec == pt
    
    # Tamper Ciphertext
    bad_ct = bytearray(ct)
    bad_ct[0] ^= 1
    with pytest.raises(ValueError):
        AESGCMEncryption.decrypt(key, nonce, bytes(bad_ct), ad)
        
    # Tamper AD
    with pytest.raises(ValueError):
        AESGCMEncryption.decrypt(key, nonce, ct, b"wrong_header")

def test_replay_detection():
    rp = ReplayProtector()
    nonce1 = os.urandom(12)
    nonce2 = os.urandom(12)
    
    assert rp.check_and_add(nonce1) is True
    assert rp.check_and_add(nonce1) is False # Replay
    assert rp.check_and_add(nonce2) is True

def test_security_manager_flow():
    logger = EventLogger()
    sm = SecurityManager(logger)
    
    sm.register_device("devA")
    sm.register_device("devB")
    
    # Auth and Exchange
    assert sm.authenticate_and_exchange("devA", "devB", 1) is True
    assert ("devA", "devB") in sm.sessions
    
    # Encrypt
    payload = sm.encrypt_message("devA", "devB", {"msg": "hello"}, 2)
    
    # Decrypt
    dec = sm.decrypt_message("devA", "devB", payload, 3)
    assert dec["msg"] == "hello"
    
    # Replay
    with pytest.raises(ValueError, match="Replay detected"):
        sm.decrypt_message("devA", "devB", payload, 4)

def test_authentication_failure():
    logger = EventLogger()
    sm = SecurityManager(logger)
    
    sm.register_device("devA")
    # devB not registered
    
    assert sm.authenticate_and_exchange("devA", "devB", 1) is False
    assert sm.metrics["auth_failures"] == 1

def test_no_secrets_in_logs():
    logger = EventLogger()
    sm = SecurityManager(logger)
    sm.register_device("devA")
    sm.register_device("devB")
    sm.authenticate_and_exchange("devA", "devB", 1)
    
    for event in logger.get_events():
        details_str = str(event["details"])
        assert "private_key" not in details_str.lower()
        assert "shared_secret" not in details_str.lower()
        assert "session_key" not in details_str.lower()
        
def test_experiment_executes():
    # Test that the classical baseline experiment runs successfully
    import subprocess
    result = subprocess.run(["python", "experiments/classical_security_baseline.py"], capture_output=True, text=True)
    assert result.returncode == 0
    assert "Security Simulation Summary" in result.stdout

def test_replay_isolation_between_sessions():
    logger = EventLogger()
    sm = SecurityManager(logger)
    sm.register_device("devA")
    sm.register_device("devB")
    sm.register_device("coreX")
    
    sm.authenticate_and_exchange("devA", "coreX", 1)
    sm.authenticate_and_exchange("devB", "coreX", 1)
    
    payload_a = sm.encrypt_message("devA", "coreX", {"msg": "hello"}, 2)
    nonce = payload_a.nonce
    
    sm.decrypt_message("devA", "coreX", payload_a, 3)
    
    with pytest.raises(ValueError, match="Replay detected"):
        sm.decrypt_message("devA", "coreX", payload_a, 4)
        
    payload_b = sm.encrypt_message("devB", "coreX", {"msg": "hi"}, 5)
    payload_b.nonce = nonce
    import cryptography.hazmat.primitives.ciphers.aead as aead
    session_key_b = sm.sessions[("devB", "coreX")]
    aes = aead.AESGCM(session_key_b)
    ct = aes.encrypt(nonce, b'{"msg": "hi"}', b"devB->coreX")
    payload_b.ciphertext = ct
    
    dec = sm.decrypt_message("devB", "coreX", payload_b, 6)
    assert dec["msg"] == "hi"

def test_fresh_challenge_and_transcript():
    logger = EventLogger()
    sm = SecurityManager(logger)
    sm.register_device("devA")
    sm.register_device("devB")
    
    ik_a = sm.my_identities["devA"]
    import secrets
    challenge = secrets.token_bytes(32)
    transcript = b"AUTH|" + b"devA" + b"|" + b"devB" + b"|" + challenge
    
    sig_a = Authenticator.sign(ik_a.private_key, transcript)
    
    assert Authenticator.verify(sm.identities["devA"], sig_a, transcript) is True
    
    bad_transcript1 = b"AUTH|" + b"devA" + b"|" + b"devB" + b"|" + secrets.token_bytes(32)
    assert Authenticator.verify(sm.identities["devA"], sig_a, bad_transcript1) is False
    
    bad_transcript2 = b"AUTH|" + b"devX" + b"|" + b"devB" + b"|" + challenge
    assert Authenticator.verify(sm.identities["devA"], sig_a, bad_transcript2) is False

