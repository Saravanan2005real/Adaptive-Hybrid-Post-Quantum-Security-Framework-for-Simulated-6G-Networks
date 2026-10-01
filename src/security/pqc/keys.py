from kyber_py.ml_kem import ML_KEM_768
from dilithium_py.ml_dsa import ML_DSA_65

class PQCIdentityKey:
    def __init__(self):
        self.public_key, self.private_key = ML_DSA_65.keygen()

class PQCEphemeralKey:
    def __init__(self):
        self.public_key, self.private_key = ML_KEM_768.keygen()
