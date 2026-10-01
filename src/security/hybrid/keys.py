from src.security.keys import IdentityKey, EphemeralKey
from src.security.pqc.keys import PQCIdentityKey, PQCEphemeralKey

class HybridIdentityKey:
    def __init__(self):
        self.classical = IdentityKey()
        self.pqc = PQCIdentityKey()

class HybridEphemeralKey:
    def __init__(self):
        self.classical = EphemeralKey()
        self.pqc = PQCEphemeralKey()
