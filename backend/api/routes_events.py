"""
AEGIS Events API
Receives OS events from the eBPF agent, scores them with AI,
and broadcasts results to connected dashboards via WebSocket.
"""

from fastapi import APIRouter
from core.models import OSEvent, EventBatch, ScoredEvent, ThreatLevel
from ai.predictor import score_event, get_model_status
from crypto.audit_chain import create_audit_entry
from db.supabase_client import db
from api.routes_ws import broadcast_event
import asyncio

router = APIRouter()

# In-memory recent events cache for quick dashboard access
_recent_events_cache: list = []
MAX_CACHE_SIZE = 1000


def classify_level(score: float) -> str:
    """Classify threat level based on anomaly score."""
    if score < 30:
        return "safe"
    elif score < 70:
        return "warning"
    else:
        return "danger"


@router.post("/events")
async def receive_events(batch: EventBatch):
    """
    Receive a batch of OS events from the eBPF agent.
    Each event is scored by the AI engine and broadcast to all connected dashboards.
    High-threat events are automatically saved to the tamper-proof audit chain.
    """
    global _recent_events_cache
    results = []

    for event in batch.events:
        event_dict = event.dict()

        # Run AI anomaly scoring (in thread to avoid blocking async loop)
        threat_score = await asyncio.to_thread(score_event, event_dict)
        event_dict["threat_score"] = round(threat_score, 2)
        event_dict["threat_level"] = classify_level(threat_score)

        # Cache for quick access
        _recent_events_cache.insert(0, event_dict)
        if len(_recent_events_cache) > MAX_CACHE_SIZE:
            _recent_events_cache = _recent_events_cache[:MAX_CACHE_SIZE]

        # If warning or dangerous, save to audit chain
        if threat_score >= 30:
            try:
                last_entries = db.select(
                    "audit_logs",
                    order_by="created_at",
                    desc=True,
                    limit=1
                )
                prev_hash = last_entries[0]["hash"] if last_entries else "0" * 64
                entry = create_audit_entry(event_dict, prev_hash)
                db.insert("audit_logs", entry)
            except Exception as e:
                print(f"[Events] Audit log save failed: {e}")

        # Save to recent events for dashboard
        try:
            db.insert("recent_events", {
                "process": event_dict.get("process", ""),
                "pid": event_dict.get("pid", 0),
                "file_path": event_dict.get("file", ""),
                "network_ip": event_dict.get("ip", "127.0.0.1"),
                "port": event_dict.get("port", 0),
                "threat_score": event_dict.get("threat_score", 0),
                "threat_level": event_dict.get("threat_level", "safe"),
                "event_type": event_dict.get("type", "file_open")
            })
        except Exception:
            pass  # Non-critical — cache is primary

        # Broadcast to all connected WebSocket dashboards
        await broadcast_event(event_dict)
        results.append(event_dict)

    return {
        "processed": len(results),
        "dangers": sum(1 for r in results if r["threat_level"] == "danger"),
        "warnings": sum(1 for r in results if r["threat_level"] == "warning")
    }


@router.get("/events/recent")
async def get_recent_events(limit: int = 100):
    """Get the most recent events from cache."""
    return _recent_events_cache[:limit]


@router.get("/events/stats")
async def get_event_stats():
    """Get aggregated event statistics."""
    events = _recent_events_cache

    if not events:
        return {
            "total_events": 0,
            "safe_count": 0,
            "warning_count": 0,
            "danger_count": 0,
            "avg_score": 0,
            "max_score": 0
        }

    scores = [e.get("threat_score", 0) for e in events]

    return {
        "total_events": len(events),
        "safe_count": sum(1 for e in events if e.get("threat_level") == "safe"),
        "warning_count": sum(1 for e in events if e.get("threat_level") == "warning"),
        "danger_count": sum(1 for e in events if e.get("threat_level") == "danger"),
        "avg_score": round(sum(scores) / len(scores), 2),
        "max_score": round(max(scores), 2)
    }


@router.get("/events/model-status")
async def model_status():
    """Get the current AI model status."""
    return get_model_status()
