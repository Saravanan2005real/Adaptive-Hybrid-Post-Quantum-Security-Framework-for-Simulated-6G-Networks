from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

class KeyExchange:
    @staticmethod
    def derive_shared_secret(private_key, peer_public_key) -> bytes:
        return private_key.exchange(peer_public_key)

    @staticmethod
    def derive_session_key(shared_secret: bytes, salt: bytes = None) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"AERIS-PQ6G-Classical-Session"
        )
        return hkdf.derive(shared_secret)
