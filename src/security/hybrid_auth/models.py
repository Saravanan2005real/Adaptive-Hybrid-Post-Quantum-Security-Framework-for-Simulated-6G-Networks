from dataclasses import dataclass
from typing import Tuple

@dataclass
class AuthRequest:
    initiator_id: str
    attempt_id: str

@dataclass
class AuthChallenge:
    attempt_id: str
    challenge: bytes
    responder_id: str

@dataclass
class AuthResponse:
    initiator_id: str
    attempt_id: str
    challenge: bytes
    classical_signature: bytes
    pqc_signature: bytes
