from dilithium_py.ml_dsa import ML_DSA_65

class PQCAuthenticator:
    @staticmethod
    def sign(private_key: bytes, message: bytes) -> bytes:
        return ML_DSA_65.sign(private_key, message)
        
    @staticmethod
    def verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
        try:
            return ML_DSA_65.verify(public_key, message, signature)
        except Exception:
            return False
