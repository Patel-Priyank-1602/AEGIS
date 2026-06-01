"""
AEGIS Encryption Module
Provides AES-256 encryption utilities for securing sensitive data at rest.
"""

import os
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def generate_key() -> str:
    """Generate a new Fernet encryption key."""
    return Fernet.generate_key().decode()


def derive_key_from_password(password: str, salt: bytes = None) -> tuple:
    """
    Derive an encryption key from a password using PBKDF2.
    
    Args:
        password: The password to derive from
        salt: Optional salt (generated if not provided)
    
    Returns:
        Tuple of (key, salt) — both as base64-encoded strings
    """
    if salt is None:
        salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

    return key.decode(), base64.b64encode(salt).decode()


def encrypt_data(data: dict, key: str) -> str:
    """Encrypt a dictionary using Fernet (AES-256-CBC)."""
    cipher = Fernet(key.encode())
    json_str = json.dumps(data, sort_keys=True)
    return cipher.encrypt(json_str.encode()).decode()


def decrypt_data(encrypted: str, key: str) -> dict:
    """Decrypt an encrypted string back to a dictionary."""
    cipher = Fernet(key.encode())
    decrypted = cipher.decrypt(encrypted.encode()).decode()
    return json.loads(decrypted)
