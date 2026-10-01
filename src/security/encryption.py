import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

class AESGCMEncryption:
    @staticmethod
    def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = None) -> tuple[bytes, bytes]:
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext_with_tag

    @staticmethod
    def decrypt(key: bytes, nonce: bytes, ciphertext_with_tag: bytes, associated_data: bytes = None) -> bytes:
        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
        except InvalidTag:
            raise ValueError("Integrity verification failed")
