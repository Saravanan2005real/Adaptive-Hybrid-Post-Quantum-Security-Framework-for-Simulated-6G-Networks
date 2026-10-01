from src.security.authentication import Authenticator
from src.security.pqc.authentication import PQCAuthenticator

class HybridAuthenticator:
    @staticmethod
    def sign(private_key_classical, private_key_pqc, message: bytes) -> tuple:
        sig_classical = Authenticator.sign(private_key_classical, message)
        sig_pqc = PQCAuthenticator.sign(private_key_pqc, message)
        return (sig_classical, sig_pqc)
        
    @staticmethod
    def verify(public_key_classical, public_key_pqc, signature: tuple, message: bytes) -> bool:
        if not isinstance(signature, tuple) or len(signature) != 2:
            return False
            
        sig_classical, sig_pqc = signature
        
        valid_classical = Authenticator.verify(public_key_classical, sig_classical, message)
        valid_pqc = PQCAuthenticator.verify(public_key_pqc, sig_pqc, message)
        
        return valid_classical and valid_pqc
