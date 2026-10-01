class Authenticator:
    @staticmethod
    def sign(private_key, data: bytes) -> bytes:
        return private_key.sign(data)

    @staticmethod
    def verify(public_key, signature: bytes, data: bytes) -> bool:
        try:
            public_key.verify(signature, data)
            return True
        except Exception:
            return False
