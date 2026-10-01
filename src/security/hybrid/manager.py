import time
import json
import secrets
from typing import Dict, Any

from src.events import EventLogger, EventType
from src.security.manager import ProtectedMessagePayload
from src.security.encryption import AESGCMEncryption
from src.security.replay import ReplayProtector

from src.security.hybrid.keys import HybridIdentityKey, HybridEphemeralKey
from src.security.hybrid.authentication import HybridAuthenticator
from src.security.hybrid.key_exchange import HybridKeyExchange

from src.security.key_exchange import KeyExchange
from src.security.pqc.key_exchange import PQCKeyExchange

class HybridSecurityManager:
    def __init__(self, logger: EventLogger):
        self.logger = logger
        self.identities = {} # entity_id -> (classical_pk, pqc_pk)
        self.sessions = {} # (entity1, entity2) -> (session_id, session_key)
        self.replays = {} # (sender_id, receiver_id, session_id) -> ReplayProtector
        self.my_identities = {} # entity_id -> HybridIdentityKey
        
        # Metrics
        self.metrics = {
            "classical_auth_latency_ms": 0.0,
            "pqc_auth_latency_ms": 0.0,
            "total_auth_latency_ms": 0.0,
            
            "classical_key_exchange_latency_ms": 0.0,
            "pqc_key_exchange_latency_ms": 0.0,
            "total_key_exchange_latency_ms": 0.0,
            
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
        ik = HybridIdentityKey()
        self.my_identities[entity_id] = ik
        self.identities[entity_id] = (ik.classical.public_key, ik.pqc.public_key)

    def authenticate_and_exchange(self, initiator_id: str, responder_id: str, timestamp: int) -> bool:
        self.logger.log(EventType.AUTHENTICATION_REQUEST, timestamp, initiator=initiator_id, responder=responder_id, security_mode="HYBRID")
        
        t0_auth = time.perf_counter()
        
        if initiator_id not in self.my_identities or responder_id not in self.my_identities:
            self.metrics["auth_failures"] += 1
            self.logger.log(EventType.AUTHENTICATION_FAILURE, timestamp, initiator=initiator_id, responder=responder_id, security_mode="HYBRID")
            return False

        initiator_ik = self.my_identities[initiator_id]
        responder_ik = self.my_identities[responder_id]

        challenge = secrets.token_bytes(32)
        transcript = b"AERIS-PQ6G-HYBRID-AUTH|" + initiator_id.encode('utf-8') + b"|" + responder_id.encode('utf-8') + b"|" + challenge
        
        # We need to measure classical vs PQC separately, so we manually do the timing here
        # Classical Signatures
        t0_class_auth = time.perf_counter()
        sig_init_class = initiator_ik.classical.private_key.sign(transcript)
        sig_resp_class = responder_ik.classical.private_key.sign(transcript)
        
        valid_init_class = True
        try:
            self.identities[initiator_id][0].verify(sig_init_class, transcript)
        except Exception:
            valid_init_class = False
            
        valid_resp_class = True
        try:
            self.identities[responder_id][0].verify(sig_resp_class, transcript)
        except Exception:
            valid_resp_class = False
            
        t1_class_auth = time.perf_counter()
        self.metrics["classical_auth_latency_ms"] += (t1_class_auth - t0_class_auth) * 1000
        
        # PQC Signatures
        t0_pqc_auth = time.perf_counter()
        from src.security.pqc.authentication import PQCAuthenticator
        sig_init_pqc = PQCAuthenticator.sign(initiator_ik.pqc.private_key, transcript)
        sig_resp_pqc = PQCAuthenticator.sign(responder_ik.pqc.private_key, transcript)
        
        valid_init_pqc = PQCAuthenticator.verify(self.identities[initiator_id][1], sig_init_pqc, transcript)
        valid_resp_pqc = PQCAuthenticator.verify(self.identities[responder_id][1], sig_resp_pqc, transcript)
        t1_pqc_auth = time.perf_counter()
        self.metrics["pqc_auth_latency_ms"] += (t1_pqc_auth - t0_pqc_auth) * 1000
        
        t1_auth = time.perf_counter()
        self.metrics["total_auth_latency_ms"] += (t1_auth - t0_auth) * 1000

        if not (valid_init_class and valid_resp_class and valid_init_pqc and valid_resp_pqc):
            self.metrics["auth_failures"] += 1
            self.logger.log(EventType.AUTHENTICATION_FAILURE, timestamp, initiator=initiator_id, responder=responder_id, security_mode="HYBRID")
            return False
            
        self.logger.log(EventType.AUTHENTICATION_SUCCESS, timestamp, initiator=initiator_id, responder=responder_id, security_mode="HYBRID")
        
        # Key Exchange
        self.logger.log(EventType.KEY_EXCHANGE_STARTED, timestamp, initiator=initiator_id, responder=responder_id, security_mode="HYBRID")
        t0_kx = time.perf_counter()
        
        # Classical Key Exchange
        t0_class_kx = time.perf_counter()
        ek_init_class = HybridEphemeralKey().classical
        ek_resp_class = HybridEphemeralKey().classical
        class_ss_init = KeyExchange.derive_shared_secret(ek_init_class.private_key, ek_resp_class.public_key)
        class_ss_resp = KeyExchange.derive_shared_secret(ek_resp_class.private_key, ek_init_class.public_key)
        t1_class_kx = time.perf_counter()
        self.metrics["classical_key_exchange_latency_ms"] += (t1_class_kx - t0_class_kx) * 1000
        
        if class_ss_init != class_ss_resp:
            self.metrics["key_exchange_failures"] += 1
            self.logger.log(EventType.KEY_EXCHANGE_FAILURE, timestamp, initiator=initiator_id, responder=responder_id, security_mode="HYBRID")
            return False

        # PQC Key Exchange
        t0_pqc_kx = time.perf_counter()
        kem_resp_pqc = HybridEphemeralKey().pqc
        pqc_ss_init, ciphertext = PQCKeyExchange.encapsulate(kem_resp_pqc.public_key)
        try:
            pqc_ss_resp = PQCKeyExchange.decapsulate(kem_resp_pqc.private_key, ciphertext)
        except Exception:
            self.metrics["key_exchange_failures"] += 1
            self.logger.log(EventType.KEY_EXCHANGE_FAILURE, timestamp, initiator=initiator_id, responder=responder_id, security_mode="HYBRID")
            return False
            
        t1_pqc_kx = time.perf_counter()
        self.metrics["pqc_key_exchange_latency_ms"] += (t1_pqc_kx - t0_pqc_kx) * 1000
        
        if pqc_ss_init != pqc_ss_resp:
            self.metrics["key_exchange_failures"] += 1
            self.logger.log(EventType.KEY_EXCHANGE_FAILURE, timestamp, initiator=initiator_id, responder=responder_id, security_mode="HYBRID")
            return False
            
        session_key = HybridKeyExchange.derive_session_key(class_ss_init, pqc_ss_init)
        t1_kx = time.perf_counter()
        self.metrics["total_key_exchange_latency_ms"] += (t1_kx - t0_kx) * 1000
        
        session_id = secrets.token_hex(16)

        self.sessions[(initiator_id, responder_id)] = (session_id, session_key)
        self.sessions[(responder_id, initiator_id)] = (session_id, session_key)
        self.replays[(initiator_id, responder_id, session_id)] = ReplayProtector()
        self.replays[(responder_id, initiator_id, session_id)] = ReplayProtector()
        
        self.metrics["authenticated_sessions"] += 1
        self.logger.log(EventType.KEY_EXCHANGE_SUCCESS, timestamp, initiator=initiator_id, responder=responder_id, security_mode="HYBRID")
        
        return True

    def encrypt_message(self, sender_id: str, receiver_id: str, payload_dict: Dict[str, Any], timestamp: int) -> ProtectedMessagePayload:
        session_data = self.sessions.get((sender_id, receiver_id))
        if not session_data:
            self.metrics["encryption_failures"] += 1
            raise ValueError("No session established")
            
        session_id, session_key = session_data
        plaintext = json.dumps(payload_dict).encode('utf-8')
        associated_data = f"{sender_id}->{receiver_id}|HYBRID|{session_id}".encode()
        
        t0 = time.perf_counter()
        nonce, ciphertext = AESGCMEncryption.encrypt(session_key, plaintext, associated_data=associated_data)
        t1 = time.perf_counter()
        self.metrics["encryption_latency_ms"] += (t1 - t0) * 1000
        
        self.logger.log(EventType.MESSAGE_ENCRYPTED, timestamp, sender=sender_id, receiver=receiver_id, security_mode="HYBRID")
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
            self.metrics["replays_detected"] += 1
            self.logger.log(EventType.REPLAY_DETECTED, timestamp, sender=sender_id, receiver=receiver_id, security_mode="HYBRID")
            raise ValueError("Replay detected")

        t0 = time.perf_counter()
        
        # 4. Attempt AES-GCM authentication/decryption.
        try:
            plaintext = AESGCMEncryption.decrypt(session_key, protected_payload.nonce, protected_payload.ciphertext, protected_payload.associated_data)
        except ValueError:
            self.metrics["decryption_failures"] += 1
            self.logger.log(EventType.INTEGRITY_VERIFICATION_FAILED, timestamp, sender=sender_id, receiver=receiver_id, security_mode="HYBRID")
            raise
            
        t1 = time.perf_counter()
        
        # 6. If AES-GCM succeeds: commit the nonce to the current session's ReplayProtector.
        replay_prot.add(protected_payload.nonce)
        
        self.metrics["decryption_latency_ms"] += (t1 - t0) * 1000
        self.logger.log(EventType.MESSAGE_DECRYPTED, timestamp, sender=sender_id, receiver=receiver_id, security_mode="HYBRID")
        return json.loads(plaintext.decode('utf-8'))
