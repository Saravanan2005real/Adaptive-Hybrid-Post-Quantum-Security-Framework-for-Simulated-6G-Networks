from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class HybridKeyExchange:
    @staticmethod
    def derive_session_key(classical_shared_secret: bytes, pqc_shared_secret: bytes) -> bytes:
        combined_secret = classical_shared_secret + pqc_shared_secret
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"AERIS-PQ6G-HYBRID-SESSION",
        )
        return hkdf.derive(combined_secret)
