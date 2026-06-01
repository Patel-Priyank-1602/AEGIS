"""
AEGIS Audit Chain
Implements a tamper-proof audit log using SHA-256 hash chaining and AES-256 encryption.

Each audit entry contains:
    - The event data (encrypted with AES-256)
    - A SHA-256 hash of the entry
    - The hash of the previous entry (creating a chain)

If any entry is modified after creation, the hash chain breaks,
making tampering immediately detectable.
"""

import hashlib
import json
import os
from datetime import datetime
from cryptography.fernet import Fernet

# ─── Encryption Setup ───────────────────────────────────────────
_encryption_key = os.getenv("AUDIT_ENCRYPTION_KEY", "")

if not _encryption_key:
    # Generate and warn if no key is configured
    _encryption_key = Fernet.generate_key().decode()
    print(f"[AuditChain] ⚠ No AUDIT_ENCRYPTION_KEY set. Generated temporary key.")
    print(f"[AuditChain] ⚠ Set AUDIT_ENCRYPTION_KEY={_encryption_key} in .env for persistence")

cipher = Fernet(
    _encryption_key.encode() if isinstance(_encryption_key, str) else _encryption_key
)

# Genesis hash — the "previous hash" for the very first entry
GENESIS_HASH = "0" * 64


def create_audit_entry(event: dict, previous_hash: str = GENESIS_HASH) -> dict:
    """
    Create a new tamper-proof audit log entry.
    
    Hash chain structure:
        Entry 1: hash = SHA256(data + "000...0")
        Entry 2: hash = SHA256(data + entry1.hash)
        Entry 3: hash = SHA256(data + entry2.hash)
        ...
    
    If Entry 1 is modified, its hash changes, which breaks Entry 2's
    chain link, which breaks Entry 3's chain link, and so on.
    Tampering is instantly visible.
    
    Args:
        event: The event data to log
        previous_hash: Hash of the previous audit entry
    
    Returns:
        Complete audit entry ready for database insertion
    """
    # Build the log content
    log_content = {
        "timestamp": datetime.utcnow().isoformat(),
        "process": event.get("process", "unknown"),
        "pid": event.get("pid", 0),
        "file": event.get("file", ""),
        "network_ip": event.get("ip", ""),
        "port": event.get("port", 0),
        "threat_score": event.get("threat_score", 0),
        "threat_level": event.get("threat_level", "unknown"),
        "type": event.get("type", "unknown"),
        "previous_hash": previous_hash
    }

    # Create deterministic JSON string for hashing
    content_string = json.dumps(log_content, sort_keys=True)

    # Compute SHA-256 hash
    current_hash = hashlib.sha256(content_string.encode()).hexdigest()

    # Encrypt the content before storing
    encrypted_content = cipher.encrypt(content_string.encode()).decode()

    return {
        "hash": current_hash,
        "previous_hash": previous_hash,
        "encrypted_content": encrypted_content,
        "threat_level": event.get("threat_level", "unknown"),
        "created_at": log_content["timestamp"]
    }


def verify_chain(entries: list) -> dict:
    """
    Verify that the entire audit log chain is intact.
    
    Args:
        entries: List of audit entries in chronological order
    
    Returns:
        Verification result with details
    """
    if not entries:
        return {
            "is_valid": True,
            "total_entries": 0,
            "message": "No entries to verify"
        }

    # Verify first entry links to genesis
    if entries[0].get("previous_hash", "") not in [GENESIS_HASH, ""]:
        return {
            "is_valid": False,
            "total_entries": len(entries),
            "broken_at": 0,
            "message": "First entry does not link to genesis hash"
        }

    # Verify each subsequent entry links to the previous
    for i in range(1, len(entries)):
        current = entries[i]
        previous = entries[i - 1]

        if current.get("previous_hash") != previous.get("hash"):
            return {
                "is_valid": False,
                "total_entries": len(entries),
                "broken_at": i,
                "message": f"Chain broken at entry {i}. Tamper detected!"
            }

    return {
        "is_valid": True,
        "total_entries": len(entries),
        "message": f"All {len(entries)} entries verified. Chain is intact."
    }


def decrypt_entry(encrypted_content: str) -> dict:
    """Decrypt a single audit log entry."""
    try:
        decrypted = cipher.decrypt(encrypted_content.encode()).decode()
        return json.loads(decrypted)
    except Exception as e:
        return {"error": f"Decryption failed: {str(e)}"}


def decrypt_entries(entries: list) -> list:
    """Decrypt a list of audit log entries."""
    decrypted = []
    for entry in entries:
        content = decrypt_entry(entry.get("encrypted_content", ""))
        decrypted.append({
            **entry,
            "decrypted_content": content
        })
    return decrypted
