import time
import json
import secrets
from typing import Dict, Any

from src.events import EventLogger, EventType
from src.security.manager import ProtectedMessagePayload
from src.security.encryption import AESGCMEncryption
from src.security.replay import ReplayProtector

from src.security.pqc.keys import PQCIdentityKey, PQCEphemeralKey
from src.security.pqc.authentication import PQCAuthenticator
from src.security.pqc.key_exchange import PQCKeyExchange

class PQCSecurityManager:
    def __init__(self, logger: EventLogger):
        self.logger = logger
        self.identities = {} # entity_id -> ML-DSA public_key
        self.sessions = {} # (entity1, entity2) -> (session_id, session_key)
        self.replays = {} # (sender_id, receiver_id, session_id) -> ReplayProtector
        self.my_identities = {} # entity_id -> PQCIdentityKey
        
        # Metrics
        self.metrics = {
            "pqc_auth_latency_ms": 0.0,
            "ml_kem_key_exchange_latency_ms": 0.0,
            "encryption_latency_ms": 0.0,
            "decryption_latency_ms": 0.0,
            "authenticated_sessions": 0,
            "auth_failures": 0,
            "key_exchange_failures": 0,
            "encryption_failures": 0,
            "decryption_failures": 0,
            "replays_detected": 0
        }

    def register_device(self, entity_id: str):
        ik = PQCIdentityKey()
        self.my_identities[entity_id] = ik
        self.identities[entity_id] = ik.public_key

    def authenticate_and_exchange(self, initiator_id: str, responder_id: str, timestamp: int) -> bool:
        self.logger.log(EventType.AUTHENTICATION_REQUEST, timestamp, initiator=initiator_id, responder=responder_id, security_mode="PQC")
        
        t0 = time.perf_counter()
        
        if initiator_id not in self.my_identities or responder_id not in self.my_identities:
            self.metrics["auth_failures"] += 1
            self.logger.log(EventType.AUTHENTICATION_FAILURE, timestamp, initiator=initiator_id, responder=responder_id, security_mode="PQC")
            return False

        initiator_ik = self.my_identities[initiator_id]
        responder_ik = self.my_identities[responder_id]

        challenge = secrets.token_bytes(32)
        transcript = b"PQC-AUTH|" + initiator_id.encode('utf-8') + b"|" + responder_id.encode('utf-8') + b"|" + challenge
        
        sig_init = PQCAuthenticator.sign(initiator_ik.private_key, transcript)
        sig_resp = PQCAuthenticator.sign(responder_ik.private_key, transcript)

        valid_init = PQCAuthenticator.verify(self.identities[initiator_id], sig_init, transcript)
        valid_resp = PQCAuthenticator.verify(self.identities[responder_id], sig_resp, transcript)
        
        t1 = time.perf_counter()
        self.metrics["pqc_auth_latency_ms"] += (t1 - t0) * 1000

        if not (valid_init and valid_resp):
            self.metrics["auth_failures"] += 1
            self.logger.log(EventType.AUTHENTICATION_FAILURE, timestamp, initiator=initiator_id, responder=responder_id, security_mode="PQC")
            return False
            
        self.logger.log(EventType.AUTHENTICATION_SUCCESS, timestamp, initiator=initiator_id, responder=responder_id, security_mode="PQC")
        
        # Key Exchange using ML-KEM
        self.logger.log(EventType.KEY_EXCHANGE_STARTED, timestamp, initiator=initiator_id, responder=responder_id, security_mode="PQC")
        t2 = time.perf_counter()
        
        # Responder generates ML-KEM key pair
        kem_resp = PQCEphemeralKey()

        # Initiator encapsulates using Responder's public key
        shared_secret_init, ciphertext = PQCKeyExchange.encapsulate(kem_resp.public_key)

        # Responder decapsulates
        try:
            shared_secret_resp = PQCKeyExchange.decapsulate(kem_resp.private_key, ciphertext)
        except Exception:
            self.metrics["key_exchange_failures"] += 1
            self.logger.log(EventType.KEY_EXCHANGE_FAILURE, timestamp, initiator=initiator_id, responder=responder_id, security_mode="PQC")
            return False

        if shared_secret_init != shared_secret_resp:
            self.metrics["key_exchange_failures"] += 1
            self.logger.log(EventType.KEY_EXCHANGE_FAILURE, timestamp, initiator=initiator_id, responder=responder_id, security_mode="PQC")
            return False
            
        session_key = PQCKeyExchange.derive_session_key(shared_secret_init)
        t3 = time.perf_counter()
        self.metrics["ml_kem_key_exchange_latency_ms"] += (t3 - t2) * 1000
        
        session_id = secrets.token_hex(16)

        self.sessions[(initiator_id, responder_id)] = (session_id, session_key)
        self.sessions[(responder_id, initiator_id)] = (session_id, session_key)
        self.replays[(initiator_id, responder_id, session_id)] = ReplayProtector()
        self.replays[(responder_id, initiator_id, session_id)] = ReplayProtector()
        
        self.metrics["authenticated_sessions"] += 1
        self.logger.log(EventType.KEY_EXCHANGE_SUCCESS, timestamp, initiator=initiator_id, responder=responder_id, security_mode="PQC")
        
        return True

    def encrypt_message(self, sender_id: str, receiver_id: str, payload_dict: Dict[str, Any], timestamp: int) -> ProtectedMessagePayload:
        session_data = self.sessions.get((sender_id, receiver_id))
        if not session_data:
            self.metrics["encryption_failures"] += 1
            raise ValueError("No session established")
            
        session_id, session_key = session_data
        plaintext = json.dumps(payload_dict).encode('utf-8')
        associated_data = f"{sender_id}->{receiver_id}|PQC|{session_id}".encode()
        
        t0 = time.perf_counter()
        nonce, ciphertext = AESGCMEncryption.encrypt(session_key, plaintext, associated_data=associated_data)
        t1 = time.perf_counter()
        self.metrics["encryption_latency_ms"] += (t1 - t0) * 1000
        
        self.logger.log(EventType.MESSAGE_ENCRYPTED, timestamp, sender=sender_id, receiver=receiver_id, security_mode="PQC")
        return ProtectedMessagePayload(nonce=nonce, ciphertext=ciphertext, associated_data=associated_data, session_id=session_id)

    def decrypt_message(self, sender_id: str, receiver_id: str, protected_payload: ProtectedMessagePayload, timestamp: int) -> Dict[str, Any]:
        session_data = self.sessions.get((receiver_id, sender_id))
        if not session_data:
            self.metrics["decryption_failures"] += 1
            raise ValueError("No session established")
            
        expected_session_id, session_key = session_data
        
        if protected_payload.session_id != expected_session_id:
            self.metrics["decryption_failures"] += 1
            raise ValueError("Session ID mismatch")
            
        replay_prot = self.replays.get((sender_id, receiver_id, expected_session_id))
        
        # 3. Check whether nonce is already present in the current session's replay state.
        if not replay_prot or replay_prot.is_seen(protected_payload.nonce):
            # 4. If already present: emit REPLAY_DETECTED and reject immediately.
            self.metrics["replays_detected"] += 1
            self.logger.log(EventType.REPLAY_DETECTED, timestamp, sender=sender_id, receiver=receiver_id, security_mode="PQC")
            raise ValueError("Replay detected")

        t0 = time.perf_counter()
        
        # 5. Attempt AES-GCM authentication/decryption.
        try:
            plaintext = AESGCMEncryption.decrypt(session_key, protected_payload.nonce, protected_payload.ciphertext, protected_payload.associated_data)
        except ValueError:
            # 6. If AES-GCM authentication fails: emit INTEGRITY_VERIFICATION_FAILED
            self.metrics["decryption_failures"] += 1
            self.logger.log(EventType.INTEGRITY_VERIFICATION_FAILED, timestamp, sender=sender_id, receiver=receiver_id, security_mode="PQC")
            raise
            
        t1 = time.perf_counter()
        
        # 7. If AES-GCM succeeds: commit the nonce to the current session's ReplayProtector.
        replay_prot.add(protected_payload.nonce)
        
        self.metrics["decryption_latency_ms"] += (t1 - t0) * 1000
        self.logger.log(EventType.MESSAGE_DECRYPTED, timestamp, sender=sender_id, receiver=receiver_id, security_mode="PQC")
        return json.loads(plaintext.decode('utf-8'))
