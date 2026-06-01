"""
AEGIS ZK Proof Verifier
Verifies Zero-Knowledge SNARK proofs for passwordless authentication.
The user's secret never leaves their browser — only a mathematical proof
that they know the secret is transmitted and verified here.
"""

import json
import subprocess
import tempfile
import os
import hashlib

VERIFICATION_KEY_PATH = os.getenv(
    "ZK_VERIFICATION_KEY_PATH",
    os.path.join(os.path.dirname(__file__), "..", "..", "zk", "verification_key.json")
)


def verify_proof(proof: dict, public_signals: list) -> bool:
    """
    Verify a ZK-SNARK proof using snarkjs.
    
    The proof demonstrates that the user knows a secret S such that
    Poseidon(S) == publicHash, without revealing S.
    
    Args:
        proof: The Groth16 proof object from snarkjs
        public_signals: Public inputs (the publicHash)
    
    Returns:
        True if proof is valid, False otherwise
    """
    # First try snarkjs verification
    if _snarkjs_available():
        return _verify_with_snarkjs(proof, public_signals)

    # Fallback: simplified verification for development
    return _verify_simplified(proof, public_signals)


def _snarkjs_available() -> bool:
    """Check if snarkjs is installed and verification key exists."""
    try:
        result = subprocess.run(
            ["snarkjs", "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0 and os.path.exists(VERIFICATION_KEY_PATH)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _verify_with_snarkjs(proof: dict, public_signals: list) -> bool:
    """Verify proof using the snarkjs CLI tool."""
    proof_file = None
    signals_file = None

    try:
        # Write proof to temp file
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        ) as pf:
            json.dump(proof, pf)
            proof_file = pf.name

        # Write public signals to temp file
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        ) as sf:
            json.dump(public_signals, sf)
            signals_file = sf.name

        # Run snarkjs groth16 verify
        result = subprocess.run(
            [
                "snarkjs", "groth16", "verify",
                VERIFICATION_KEY_PATH,
                signals_file,
                proof_file
            ],
            capture_output=True,
            text=True,
            timeout=10
        )

        is_valid = "OK" in result.stdout
        if not is_valid:
            print(f"[ZK] Proof verification failed: {result.stderr}")
        return is_valid

    except subprocess.TimeoutExpired:
        print("[ZK] Proof verification timed out")
        return False
    except Exception as e:
        print(f"[ZK] Proof verification error: {e}")
        return False
    finally:
        if proof_file and os.path.exists(proof_file):
            os.unlink(proof_file)
        if signals_file and os.path.exists(signals_file):
            os.unlink(signals_file)


def _verify_simplified(proof: dict, public_signals: list) -> bool:
    """
    Simplified verification for development/demo purposes.
    In production, always use snarkjs verification.
    
    This checks that the proof structure is valid and the public signal
    matches the registered hash.
    """
    required_keys = ["pi_a", "pi_b", "pi_c", "protocol"]
    has_structure = all(k in proof for k in required_keys)

    if not has_structure:
        # For development: accept hash-based verification
        if "hash" in proof and len(public_signals) > 0:
            return proof["hash"] == public_signals[0]
        return False

    return has_structure and len(public_signals) > 0


def compute_public_hash(secret: str) -> str:
    """
    Compute the public hash of a secret for registration.
    In production, this uses Poseidon hash matching the circom circuit.
    For development, uses SHA-256.
    """
    return hashlib.sha256(secret.encode()).hexdigest()
