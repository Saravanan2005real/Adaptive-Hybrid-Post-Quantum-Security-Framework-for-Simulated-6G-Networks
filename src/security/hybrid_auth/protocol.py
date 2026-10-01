import time
import secrets
from typing import Dict, Any, Tuple

from src.events import EventLogger, EventType
from src.security.hybrid.keys import HybridIdentityKey
from src.security.hybrid.authentication import HybridAuthenticator
from src.security.authentication import Authenticator
from src.security.pqc.authentication import PQCAuthenticator
from src.security.hybrid_auth.state import AuthState, AuthFailureReason
from src.security.hybrid_auth.models import AuthRequest, AuthChallenge, AuthResponse

class HybridAuthProtocol:
    def __init__(self, logger: EventLogger, challenge_ttl_seconds: float = 30.0, time_func=time.time):
        self.logger = logger
        self.challenge_ttl_seconds = challenge_ttl_seconds
        self.time_func = time_func
        
        self.my_identities: Dict[str, HybridIdentityKey] = {}
        self.identities: Dict[str, Tuple[Any, Any]] = {}
        
        self.attempts: Dict[str, Dict[str, Any]] = {}
        self.consumed_challenges = set()
        
        self.metrics = {
            "authentication_attempts": 0,
            "successful_authentications": 0,
            "failed_authentications": 0,
            "protocol_rejections": 0,
            "classical_signature_failures": 0,
            "pqc_signature_failures": 0,
            "expired_challenges": 0,
            "replayed_challenges": 0,
            "mutual_authentication_successes": 0,
            "authentication_latency": 0.0
        }
        
    def register_device(self, entity_id: str):
        ik = HybridIdentityKey()
        self.my_identities[entity_id] = ik
        self.identities[entity_id] = (ik.classical.public_key, ik.pqc.public_key)
        
    def create_request(self, initiator_id: str, responder_id: str) -> AuthRequest:
        attempt_id = secrets.token_hex(16)
        self.attempts[attempt_id] = {
            "initiator": initiator_id,
            "responder": responder_id,
            "state": AuthState.AUTH_REQUESTED,
            "timestamp": self.time_func(),
            "challenge": None,
            "initiator_authenticated": False,
            "responder_authenticated": False
        }
        self.metrics["authentication_attempts"] += 1
        self.logger.log(EventType.HYBRID_AUTH_REQUESTED, self.time_func(), initiator=initiator_id, responder=responder_id, attempt_id=attempt_id)
        return AuthRequest(initiator_id, attempt_id)

    def issue_challenge(self, request: AuthRequest, responder_id: str) -> AuthChallenge:
        attempt_id = request.attempt_id
        if attempt_id not in self.attempts:
            self._reject(attempt_id, AuthFailureReason.INVALID_ATTEMPT)
        
        attempt = self.attempts[attempt_id]
        if attempt["state"] != AuthState.AUTH_REQUESTED:
            self._reject(attempt_id, AuthFailureReason.INVALID_STATE)
            
        if attempt["initiator"] != request.initiator_id or attempt["responder"] != responder_id:
            self._reject(attempt_id, AuthFailureReason.INVALID_IDENTITY)
            
        if request.initiator_id not in self.identities or responder_id not in self.my_identities:
            self._reject(attempt_id, AuthFailureReason.INVALID_IDENTITY)

        challenge = secrets.token_bytes(32)
        attempt["challenge"] = challenge
        attempt["state"] = AuthState.CHALLENGE_ISSUED
        attempt["timestamp"] = self.time_func()
        
        self.logger.log(EventType.HYBRID_AUTH_CHALLENGE_ISSUED, self.time_func(), attempt_id=attempt_id)
        return AuthChallenge(attempt_id, challenge, responder_id)

    def respond_to_challenge(self, challenge: AuthChallenge, initiator_id: str) -> AuthResponse:
        attempt_id = challenge.attempt_id
        if attempt_id not in self.attempts:
            self._reject(attempt_id, AuthFailureReason.INVALID_ATTEMPT)
        attempt = self.attempts[attempt_id]
        
        if attempt["state"] != AuthState.CHALLENGE_ISSUED:
            self._reject(attempt_id, AuthFailureReason.INVALID_STATE)
            
        if attempt["initiator"] != initiator_id or attempt["responder"] != challenge.responder_id:
            self._reject(attempt_id, AuthFailureReason.INVALID_IDENTITY)
            
        if challenge.challenge != attempt["challenge"]:
            self._reject(attempt_id, AuthFailureReason.UNKNOWN_CHALLENGE)
            
        if self._is_expired(attempt):
            self._reject(attempt_id, AuthFailureReason.EXPIRED_CHALLENGE)
            
        ik = self.my_identities[initiator_id]
        transcript = self._build_transcript("INITIATOR_AUTH", initiator_id, challenge.responder_id, challenge.challenge, attempt_id)
        
        t0 = time.perf_counter()
        sig_class, sig_pqc = HybridAuthenticator.sign(ik.classical.private_key, ik.pqc.private_key, transcript)
        t1 = time.perf_counter()
        self.metrics["authentication_latency"] += (t1 - t0) * 1000
        
        return AuthResponse(initiator_id, attempt_id, challenge.challenge, sig_class, sig_pqc)

    def verify_initiator_response(self, response: AuthResponse, responder_id: str) -> AuthResponse:
        attempt_id = response.attempt_id
        if attempt_id not in self.attempts:
            self._reject(attempt_id, AuthFailureReason.INVALID_ATTEMPT)
        attempt = self.attempts[attempt_id]
        
        if attempt["state"] not in (AuthState.CHALLENGE_ISSUED, AuthState.RESPONSE_RECEIVED):
            self._reject(attempt_id, AuthFailureReason.INVALID_STATE)
            
        if attempt["initiator"] != response.initiator_id or attempt["responder"] != responder_id:
            self._reject(attempt_id, AuthFailureReason.INVALID_IDENTITY)
            
        if response.challenge != attempt["challenge"]:
            self._reject(attempt_id, AuthFailureReason.UNKNOWN_CHALLENGE)
            
        if response.challenge in self.consumed_challenges:
            self.metrics["replayed_challenges"] += 1
            self._reject(attempt_id, AuthFailureReason.CHALLENGE_ALREADY_CONSUMED)
            
        if self._is_expired(attempt):
            self._reject(attempt_id, AuthFailureReason.EXPIRED_CHALLENGE)
            
        attempt["state"] = AuthState.RESPONSE_RECEIVED
        self.logger.log(EventType.HYBRID_AUTH_RESPONSE_RECEIVED, self.time_func(), attempt_id=attempt_id)
        
        transcript = self._build_transcript("INITIATOR_AUTH", response.initiator_id, responder_id, response.challenge, attempt_id)
        pk_class, pk_pqc = self.identities[response.initiator_id]
        
        t0 = time.perf_counter()
        valid = HybridAuthenticator.verify(pk_class, pk_pqc, (response.classical_signature, response.pqc_signature), transcript)
        t1 = time.perf_counter()
        self.metrics["authentication_latency"] += (t1 - t0) * 1000
        
        if not valid:
            self._track_sig_failures(pk_class, pk_pqc, response, transcript)
            self._fail(attempt_id, AuthFailureReason.MUTUAL_AUTHENTICATION_FAILED)
            
        attempt["initiator_authenticated"] = True
        
        # Responder creates its response to prove possession
        ik_resp = self.my_identities[responder_id]
        transcript_resp = self._build_transcript("RESPONDER_AUTH", response.initiator_id, responder_id, response.challenge, attempt_id)
        t2 = time.perf_counter()
        sig_class_resp, sig_pqc_resp = HybridAuthenticator.sign(ik_resp.classical.private_key, ik_resp.pqc.private_key, transcript_resp)
        t3 = time.perf_counter()
        self.metrics["authentication_latency"] += (t3 - t2) * 1000
        
        return AuthResponse(responder_id, attempt_id, response.challenge, sig_class_resp, sig_pqc_resp)

    def verify_responder_response(self, response: AuthResponse, initiator_id: str) -> bool:
        attempt_id = response.attempt_id
        if attempt_id not in self.attempts:
            self._reject(attempt_id, AuthFailureReason.INVALID_ATTEMPT)
        attempt = self.attempts[attempt_id]
        
        if attempt["state"] != AuthState.RESPONSE_RECEIVED:
            self._reject(attempt_id, AuthFailureReason.INVALID_STATE)
            
        if attempt["initiator"] != initiator_id or attempt["responder"] != response.initiator_id:
            self._reject(attempt_id, AuthFailureReason.INVALID_IDENTITY)
            
        if response.challenge != attempt["challenge"]:
            self._reject(attempt_id, AuthFailureReason.UNKNOWN_CHALLENGE)
            
        if response.challenge in self.consumed_challenges:
            self.metrics["replayed_challenges"] += 1
            self._reject(attempt_id, AuthFailureReason.CHALLENGE_ALREADY_CONSUMED)
            
        if self._is_expired(attempt):
            self._reject(attempt_id, AuthFailureReason.EXPIRED_CHALLENGE)
            
        transcript = self._build_transcript("RESPONDER_AUTH", initiator_id, response.initiator_id, response.challenge, attempt_id)
        pk_class, pk_pqc = self.identities[response.initiator_id]
        
        t0 = time.perf_counter()
        valid = HybridAuthenticator.verify(pk_class, pk_pqc, (response.classical_signature, response.pqc_signature), transcript)
        t1 = time.perf_counter()
        self.metrics["authentication_latency"] += (t1 - t0) * 1000
        
        if not valid:
            self._track_sig_failures(pk_class, pk_pqc, response, transcript)
            self._fail(attempt_id, AuthFailureReason.MUTUAL_AUTHENTICATION_FAILED)
            
        attempt["responder_authenticated"] = True
        attempt["state"] = AuthState.AUTHENTICATED
        
        # ONLY after both sides successfully authenticate: mark challenge as consumed
        self.consumed_challenges.add(response.challenge)
        
        self.metrics["successful_authentications"] += 1
        self.metrics["mutual_authentication_successes"] += 1
        self.logger.log(EventType.HYBRID_AUTH_VERIFICATION_SUCCESS, self.time_func(), attempt_id=attempt_id)
        return True

    def _build_transcript(self, role: str, initiator_id: str, responder_id: str, challenge: bytes, attempt_id: str) -> bytes:
        return b"AERIS-PQ6G-HYBRID-AUTH-V1|" + role.encode() + b"|" + initiator_id.encode() + b"|" + responder_id.encode() + b"|" + challenge + b"|" + attempt_id.encode()

    def _is_expired(self, attempt: dict) -> bool:
        return self.time_func() - attempt["timestamp"] > self.challenge_ttl_seconds

    def _track_sig_failures(self, pk_class, pk_pqc, response: AuthResponse, transcript: bytes):
        valid_class = True
        try:
            valid_class = Authenticator.verify(pk_class, response.classical_signature, transcript)
        except Exception:
            valid_class = False
            
        valid_pqc = True
        try:
            valid_pqc = PQCAuthenticator.verify(pk_pqc, response.pqc_signature, transcript)
        except Exception:
            valid_pqc = False
            
        if not valid_class:
            self.metrics["classical_signature_failures"] += 1
        if not valid_pqc:
            self.metrics["pqc_signature_failures"] += 1

    def _reject(self, attempt_id: str, reason: AuthFailureReason):
        """Used for protocol structural/state rejections before formal authentication evaluation"""
        self.metrics["protocol_rejections"] += 1
        if attempt_id in self.attempts:
            self.attempts[attempt_id]["state"] = AuthState.AUTHENTICATION_FAILED
            
        if reason == AuthFailureReason.EXPIRED_CHALLENGE:
            self.metrics["expired_challenges"] += 1
            self.logger.log(EventType.HYBRID_AUTH_EXPIRED, self.time_func(), attempt_id=attempt_id, reason=reason.name)
        else:
            self.logger.log(EventType.HYBRID_AUTH_FAILED, self.time_func(), attempt_id=attempt_id, reason=reason.name)
        
        raise ValueError(reason.name)

    def _fail(self, attempt_id: str, reason: AuthFailureReason):
        """Used for cryptographic authentication failures"""
        self.metrics["failed_authentications"] += 1
        if attempt_id in self.attempts:
            self.attempts[attempt_id]["state"] = AuthState.AUTHENTICATION_FAILED
        self.logger.log(EventType.HYBRID_AUTH_FAILED, self.time_func(), attempt_id=attempt_id, reason=reason.name)
        raise ValueError(reason.name)
