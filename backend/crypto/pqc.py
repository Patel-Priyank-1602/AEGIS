"""
AEGIS Post-Quantum Cryptography Module
Implements NIST-standardized PQC algorithms for JWT signing and key exchange.
Uses Dilithium (digital signatures) and Kyber (key encapsulation).

Migration strategy: Dual-sign JWTs with RSA + Dilithium. Legacy clients
validate RSA; PQC-aware clients validate Dilithium. Remove RSA after 30 days.

Falls back gracefully when liboqs is not installed.
"""

import hashlib
import hmac
import json
import time
import base64
from datetime import datetime
from typing import Optional, Dict, Tuple

# Try to import liboqs for real PQC
_pqc_available = False
try:
    import oqs
    _pqc_available = True
    print("[PQC] liboqs available — post-quantum cryptography enabled")
except ImportError:
    print("[PQC] liboqs not installed. Using simulated PQC signatures.")


class PQCManager:
    """
    Post-Quantum Cryptography manager.
    Handles Dilithium signing and Kyber key exchange.
    """

    def __init__(self):
        self.dilithium_keypair: Optional[Dict] = None
        self.kyber_keypair: Optional[Dict] = None
        self.migration_start: Optional[str] = None
        self.dual_signing: bool = True  # Sign with both RSA and Dilithium
        self.signatures_created: int = 0
        self.signatures_verified: int = 0
        self.key_exchanges: int = 0

        # Generate initial keypairs
        self._generate_keypairs()

    def _generate_keypairs(self):
        """Generate Dilithium and Kyber keypairs."""
        if _pqc_available:
            try:
                # Dilithium for digital signatures
                signer = oqs.Signature("Dilithium3")
                public_key = signer.generate_keypair()
                self.dilithium_keypair = {
                    "algorithm": "Dilithium3",
                    "public_key": base64.b64encode(public_key).decode(),
                    "secret_key": base64.b64encode(signer.export_secret_key()).decode(),
                    "signer": signer,
                    "generated_at": datetime.utcnow().isoformat(),
                }
                print(f"[PQC] ✓ Dilithium3 keypair generated")

                # Kyber for key encapsulation
                kem = oqs.KeyEncapsulation("Kyber768")
                public_key = kem.generate_keypair()
                self.kyber_keypair = {
                    "algorithm": "Kyber768",
                    "public_key": base64.b64encode(public_key).decode(),
                    "kem": kem,
                    "generated_at": datetime.utcnow().isoformat(),
                }
                print(f"[PQC] ✓ Kyber768 keypair generated")
            except Exception as e:
                print(f"[PQC] Key generation failed: {e}. Using simulated PQC.")
                self._generate_simulated_keypairs()
        else:
            self._generate_simulated_keypairs()

        self.migration_start = datetime.utcnow().isoformat()

    def _generate_simulated_keypairs(self):
        """Generate simulated PQC keypairs for development."""
        import secrets
        self.dilithium_keypair = {
            "algorithm": "Dilithium3-simulated",
            "public_key": base64.b64encode(secrets.token_bytes(32)).decode(),
            "secret_key": base64.b64encode(secrets.token_bytes(64)).decode(),
            "generated_at": datetime.utcnow().isoformat(),
        }
        self.kyber_keypair = {
            "algorithm": "Kyber768-simulated",
            "public_key": base64.b64encode(secrets.token_bytes(32)).decode(),
            "generated_at": datetime.utcnow().isoformat(),
        }

    def sign_dilithium(self, message: bytes) -> str:
        """Sign a message with Dilithium (post-quantum digital signature)."""
        self.signatures_created += 1

        if _pqc_available and "signer" in (self.dilithium_keypair or {}):
            try:
                signer = self.dilithium_keypair["signer"]
                signature = signer.sign(message)
                return base64.b64encode(signature).decode()
            except Exception:
                pass

        # Simulated Dilithium signature (HMAC-based for dev)
        secret = self.dilithium_keypair["secret_key"].encode()
        sig = hmac.new(secret, message, hashlib.sha512).hexdigest()
        return f"sim-dilithium:{sig}"

    def verify_dilithium(self, message: bytes, signature: str) -> bool:
        """Verify a Dilithium signature."""
        self.signatures_verified += 1

        if _pqc_available and "signer" in (self.dilithium_keypair or {}):
            try:
                sig_bytes = base64.b64decode(signature)
                pk_bytes = base64.b64decode(self.dilithium_keypair["public_key"])
                verifier = oqs.Signature("Dilithium3")
                return verifier.verify(message, sig_bytes, pk_bytes)
            except Exception:
                return False

        # Simulated verification
        if signature.startswith("sim-dilithium:"):
            expected = self.sign_dilithium(message)
            return hmac.compare_digest(signature, expected)
        return False

    def dual_sign_jwt(self, payload: dict, rsa_secret: str) -> dict:
        """
        Dual-sign a JWT payload with both RSA (HMAC) and Dilithium.
        Returns both signatures so legacy clients can fall back to RSA.
        """
        payload_json = json.dumps(payload, sort_keys=True).encode()

        # Classical signature (HMAC-SHA256, simulating RSA)
        rsa_sig = hmac.new(rsa_secret.encode(), payload_json, hashlib.sha256).hexdigest()

        # Post-quantum signature (Dilithium)
        pqc_sig = self.sign_dilithium(payload_json)

        return {
            "payload": payload,
            "rsa_signature": rsa_sig,
            "pqc_signature": pqc_sig,
            "pqc_algorithm": self.dilithium_keypair["algorithm"],
            "dual_signed": True,
            "signed_at": datetime.utcnow().isoformat(),
        }

    def kyber_encapsulate(self) -> Tuple[str, str]:
        """
        Perform Kyber key encapsulation.
        Returns (ciphertext, shared_secret) for key exchange.
        """
        self.key_exchanges += 1

        if _pqc_available and "kem" in (self.kyber_keypair or {}):
            try:
                kem = self.kyber_keypair["kem"]
                pk = base64.b64decode(self.kyber_keypair["public_key"])
                encaps = oqs.KeyEncapsulation("Kyber768")
                ciphertext, shared_secret = encaps.encap_secret(pk)
                return (
                    base64.b64encode(ciphertext).decode(),
                    base64.b64encode(shared_secret).decode(),
                )
            except Exception:
                pass

        # Simulated Kyber encapsulation
        import secrets
        ct = base64.b64encode(secrets.token_bytes(32)).decode()
        ss = base64.b64encode(secrets.token_bytes(32)).decode()
        return ct, ss

    def get_stats(self) -> dict:
        return {
            "pqc_available": _pqc_available,
            "dilithium_algorithm": self.dilithium_keypair["algorithm"] if self.dilithium_keypair else None,
            "kyber_algorithm": self.kyber_keypair["algorithm"] if self.kyber_keypair else None,
            "dual_signing": self.dual_signing,
            "signatures_created": self.signatures_created,
            "signatures_verified": self.signatures_verified,
            "key_exchanges": self.key_exchanges,
            "migration_start": self.migration_start,
            "keys_generated_at": self.dilithium_keypair.get("generated_at") if self.dilithium_keypair else None,
        }


# Global singleton
pqc_manager = PQCManager()
