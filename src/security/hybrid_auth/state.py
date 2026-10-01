from enum import Enum, auto

class AuthState(Enum):
    IDLE = auto()
    AUTH_REQUESTED = auto()
    CHALLENGE_ISSUED = auto()
    RESPONSE_RECEIVED = auto()
    AUTHENTICATED = auto()
    AUTHENTICATION_FAILED = auto()
    EXPIRED = auto()

class AuthFailureReason(Enum):
    INVALID_IDENTITY = auto()
    INVALID_ATTEMPT = auto()
    UNKNOWN_CHALLENGE = auto()
    EXPIRED_CHALLENGE = auto()
    CHALLENGE_ALREADY_CONSUMED = auto()
    INVALID_CLASSICAL_SIGNATURE = auto()
    INVALID_PQC_SIGNATURE = auto()
    INVALID_TRANSCRIPT = auto()
    MUTUAL_AUTHENTICATION_FAILED = auto()
    INVALID_STATE = auto()
