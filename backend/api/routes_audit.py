"""
AEGIS Audit Log API
Provides access to the tamper-proof audit log chain.
Supports retrieval, verification, and export of security events.
"""

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from crypto.audit_chain import verify_chain, decrypt_entries, decrypt_entry
from db.supabase_client import db
from datetime import datetime

router = APIRouter()


@router.get("/audit")
async def get_audit_logs(
    limit: int = 50,
    threat_level: str = None,
    decrypt: bool = False
):
    """
    Retrieve audit log entries.
    
    Args:
        limit: Maximum entries to return (default 50)
        threat_level: Filter by level (safe, warning, danger)
        decrypt: If true, include decrypted content
    """
    filters = {}
    if threat_level:
        filters["threat_level"] = threat_level

    entries = db.select(
        "audit_logs",
        filters=filters if filters else None,
        order_by="created_at",
        desc=True,
        limit=limit
    )

    if decrypt and entries:
        entries = decrypt_entries(entries)

    return {
        "entries": entries,
        "total": len(entries),
        "decrypted": decrypt
    }


@router.get("/audit/{entry_id}")
async def get_audit_entry(entry_id: str, decrypt: bool = True):
    """Get a single audit log entry by ID."""
    entries = db.select("audit_logs", filters={"id": entry_id})
    if not entries:
        raise HTTPException(status_code=404, detail="Audit entry not found")

    entry = entries[0]
    if decrypt:
        content = decrypt_entry(entry.get("encrypted_content", ""))
        entry["decrypted_content"] = content

    return entry


@router.get("/audit/verify/chain")
async def verify_audit_chain():
    """
    Verify the integrity of the entire audit log chain.
    Checks that no entries have been tampered with.
    
    Returns:
        Verification result with:
        - is_valid: boolean
        - total_entries: count
        - broken_at: index where chain breaks (if tampered)
        - message: human-readable result
    """
    entries = db.select(
        "audit_logs",
        order_by="created_at",
        desc=False  # Chronological order for verification
    )

    result = verify_chain(entries)
    return result


@router.get("/audit/export/json")
async def export_audit_json(decrypt: bool = True):
    """
    Export the complete audit log as a JSON report.
    Includes chain verification status.
    """
    entries = db.select(
        "audit_logs",
        order_by="created_at",
        desc=False
    )

    # Verify chain integrity
    verification = verify_chain(entries)

    # Optionally decrypt
    if decrypt and entries:
        entries = decrypt_entries(entries)

    report = {
        "report_title": "AEGIS Security Audit Report",
        "generated_at": datetime.utcnow().isoformat(),
        "chain_verification": verification,
        "total_entries": len(entries),
        "threat_summary": {
            "danger": sum(1 for e in entries if e.get("threat_level") == "danger"),
            "warning": sum(1 for e in entries if e.get("threat_level") == "warning"),
            "safe": sum(1 for e in entries if e.get("threat_level") == "safe")
        },
        "entries": entries
    }

    return JSONResponse(
        content=report,
        headers={
            "Content-Disposition": f'attachment; filename="aegis_audit_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.json"'
        }
    )


@router.delete("/audit/clear")
async def clear_audit_logs():
    """
    Clear all audit log entries and reset the chain.
    Use after retraining the AI model to remove stale entries scored with the old model.
    """
    try:
        # For in-memory store, clear the list directly
        from db.supabase_client import _using_memory, _memory_store
        if _using_memory:
            count = len(_memory_store.audit_logs)
            _memory_store.audit_logs.clear()
            return {"cleared": count, "message": f"Cleared {count} audit entries. Chain reset."}
        else:
            # For Supabase, delete all rows
            # PostgREST requires at least one filter; use created_at not null (matches everything)
            import requests as http_requests
            from db.supabase_client import _supabase_url, _supabase_headers
            r = http_requests.delete(
                f"{_supabase_url}/audit_logs",
                headers=_supabase_headers,
                params={"created_at": "not.is.null"},
                timeout=10
            )
            if r.status_code in (200, 204):
                result = r.json() if r.text else []
                count = len(result) if isinstance(result, list) else 0
                return {"cleared": count, "message": f"Cleared {count} audit entries. Chain reset."}
            else:
                return {"cleared": 0, "message": f"Failed: {r.status_code}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
