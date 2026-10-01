import time
import json
import base64
import secrets
import base64
from typing import Dict, Any
from src.events import EventLogger, EventType
from src.security.keys import IdentityKey, EphemeralKey
from src.security.authentication import Authenticator
from src.security.key_exchange import KeyExchange
from src.security.encryption import AESGCMEncryption
from src.security.replay import ReplayProtector

class ProtectedMessagePayload:
    def __init__(self, nonce: bytes, ciphertext: bytes, associated_data: bytes = None, session_id: str = None):
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.associated_data = associated_data
        self.session_id = session_id

    def to_dict(self):
        return {
            "nonce": base64.b64encode(self.nonce).decode('utf-8'),
            "ciphertext": base64.b64encode(self.ciphertext).decode('utf-8'),
            "associated_data": base64.b64encode(self.associated_data).decode('utf-8') if self.associated_data else None,
            "session_id": self.session_id
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            nonce=base64.b64decode(data["nonce"]),
            ciphertext=base64.b64decode(data["ciphertext"]),
            associated_data=base64.b64decode(data["associated_data"]) if data.get("associated_data") else None,
            session_id=data.get("session_id")
        )

class SecurityManager:
    def __init__(self, logger: EventLogger):
        self.logger = logger
        self.identities = {} # entity_id -> public_key
        self.sessions = {} # (entity1, entity2) -> session_key
        self.replays = {} # (sender_id, receiver_id) -> ReplayProtector
        self.my_identities = {} # entity_id -> IdentityKey (mock KMS)
        
        # Metrics
        self.metrics = {
            "auth_latency_ms": 0.0,
            "key_exchange_latency_ms": 0.0,
            "encryption_latency_ms": 0.0,
            "decryption_latency_ms": 0.0,
            "authenticated_sessions": 0,
            "auth_failures": 0,
            "encryption_failures": 0,
            "decryption_failures": 0,
            "replays_detected": 0
        }

    def register_device(self, entity_id: str):
        ik = IdentityKey()
        self.my_identities[entity_id] = ik
        self.identities[entity_id] = ik.public_key

    def authenticate_and_exchange(self, initiator_id: str, responder_id: str, timestamp: int) -> bool:
        self.logger.log(EventType.AUTHENTICATION_REQUEST, timestamp, initiator=initiator_id, responder=responder_id)
        
        t0 = time.perf_counter()
        
        # Mock auth process
        if initiator_id not in self.my_identities or responder_id not in self.my_identities:
            self.metrics["auth_failures"] += 1
            self.logger.log(EventType.AUTHENTICATION_FAILURE, timestamp, initiator=initiator_id, responder=responder_id)
            return False

        initiator_ik = self.my_identities[initiator_id]
        responder_ik = self.my_identities[responder_id]

        challenge = secrets.token_bytes(32)
        transcript = b"AUTH|" + initiator_id.encode('utf-8') + b"|" + responder_id.encode('utf-8') + b"|" + challenge
        
        sig_init = Authenticator.sign(initiator_ik.private_key, transcript)
        sig_resp = Authenticator.sign(responder_ik.private_key, transcript)

        valid_init = Authenticator.verify(self.identities[initiator_id], sig_init, transcript)
        valid_resp = Authenticator.verify(self.identities[responder_id], sig_resp, transcript)
        
        t1 = time.perf_counter()
        self.metrics["auth_latency_ms"] += (t1 - t0) * 1000

        if not (valid_init and valid_resp):
            self.metrics["auth_failures"] += 1
            self.logger.log(EventType.AUTHENTICATION_FAILURE, timestamp, initiator=initiator_id, responder=responder_id)
            return False
            
        self.logger.log(EventType.AUTHENTICATION_SUCCESS, timestamp, initiator=initiator_id, responder=responder_id)
        
        # Key Exchange
        self.logger.log(EventType.KEY_EXCHANGE_STARTED, timestamp, initiator=initiator_id, responder=responder_id)
        t2 = time.perf_counter()
        
        ek_init = EphemeralKey()
        ek_resp = EphemeralKey()

        shared_secret_init = KeyExchange.derive_shared_secret(ek_init.private_key, ek_resp.public_key)
        shared_secret_resp = KeyExchange.derive_shared_secret(ek_resp.private_key, ek_init.public_key)

        if shared_secret_init != shared_secret_resp:
            self.logger.log(EventType.KEY_EXCHANGE_FAILURE, timestamp, initiator=initiator_id, responder=responder_id)
            return False
            
        session_key = KeyExchange.derive_session_key(shared_secret_init)
        t3 = time.perf_counter()
        self.metrics["key_exchange_latency_ms"] += (t3 - t2) * 1000

        self.sessions[(initiator_id, responder_id)] = session_key
        self.sessions[(responder_id, initiator_id)] = session_key
        self.replays[(initiator_id, responder_id)] = ReplayProtector()
        self.replays[(responder_id, initiator_id)] = ReplayProtector()
        
        self.metrics["authenticated_sessions"] += 1
        self.logger.log(EventType.KEY_EXCHANGE_SUCCESS, timestamp, initiator=initiator_id, responder=responder_id)
        
        return True

    def encrypt_message(self, sender_id: str, receiver_id: str, payload_dict: Dict[str, Any], timestamp: int) -> ProtectedMessagePayload:
        session_key = self.sessions.get((sender_id, receiver_id))
        if not session_key:
            self.metrics["encryption_failures"] += 1
            raise ValueError("No session established")
            
        plaintext = json.dumps(payload_dict).encode('utf-8')
        associated_data = f"{sender_id}->{receiver_id}".encode()
        
        t0 = time.perf_counter()
        nonce, ciphertext = AESGCMEncryption.encrypt(session_key, plaintext, associated_data=associated_data)
        t1 = time.perf_counter()
        self.metrics["encryption_latency_ms"] += (t1 - t0) * 1000
        
        self.logger.log(EventType.MESSAGE_ENCRYPTED, timestamp, sender=sender_id, receiver=receiver_id)
        return ProtectedMessagePayload(nonce=nonce, ciphertext=ciphertext, associated_data=associated_data)

    def decrypt_message(self, sender_id: str, receiver_id: str, protected_payload: ProtectedMessagePayload, timestamp: int) -> Dict[str, Any]:
        # Note: receiver is decrypting, so it looks up its session with sender
        session_key = self.sessions.get((receiver_id, sender_id))
        if not session_key:
            self.metrics["decryption_failures"] += 1
            raise ValueError("No session established")
            
        replay_prot = self.replays.get((sender_id, receiver_id))
        if not replay_prot.check_and_add(protected_payload.nonce):
            self.metrics["replays_detected"] += 1
            self.logger.log(EventType.REPLAY_DETECTED, timestamp, sender=sender_id, receiver=receiver_id)
            raise ValueError("Replay detected")

        t0 = time.perf_counter()
        try:
            plaintext = AESGCMEncryption.decrypt(session_key, protected_payload.nonce, protected_payload.ciphertext, protected_payload.associated_data)
        except ValueError:
            self.metrics["decryption_failures"] += 1
            self.logger.log(EventType.INTEGRITY_VERIFICATION_FAILED, timestamp, sender=sender_id, receiver=receiver_id)
            raise
            
        t1 = time.perf_counter()
        self.metrics["decryption_latency_ms"] += (t1 - t0) * 1000
        self.logger.log(EventType.MESSAGE_DECRYPTED, timestamp, sender=sender_id, receiver=receiver_id)
        return json.loads(plaintext.decode('utf-8'))
