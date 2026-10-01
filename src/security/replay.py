class ReplayProtector:
    def __init__(self):
        self.seen_nonces = set()

    def check_and_add(self, nonce: bytes) -> bool:
        if nonce in self.seen_nonces:
            return False
        self.seen_nonces.add(nonce)
        return True

    def is_seen(self, nonce: bytes) -> bool:
        return nonce in self.seen_nonces

    def add(self, nonce: bytes):
        self.seen_nonces.add(nonce)
