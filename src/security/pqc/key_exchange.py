from kyber_py.ml_kem import ML_KEM_768
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class PQCKeyExchange:
    @staticmethod
    def encapsulate(public_key: bytes):
        # returns (shared_secret, ciphertext)
        shared_secret, ciphertext = ML_KEM_768.encaps(public_key)
        return shared_secret, ciphertext
        
    @staticmethod
    def decapsulate(private_key: bytes, ciphertext: bytes) -> bytes:
        return ML_KEM_768.decaps(private_key, ciphertext)

    @staticmethod
    def derive_session_key(shared_secret: bytes) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"AERIS-PQ6G-PQC-ML-KEM-SESSION",
        )
        return hkdf.derive(shared_secret)
