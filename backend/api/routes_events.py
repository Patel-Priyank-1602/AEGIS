"""
AEGIS Events API
Receives OS events from the eBPF agent, scores them with AI,
enriches with threat intel, MITRE tags, UEBA, GNN, honeypot checks,
and broadcasts results to connected dashboards via WebSocket.

This is the main event processing pipeline where all 10 features integrate.
"""

from fastapi import APIRouter
from core.models import OSEvent, EventBatch, ScoredEvent, ThreatLevel
from ai.predictor import score_event, get_model_status
from crypto.audit_chain import create_audit_entry
from db.supabase_client import db
from api.routes_ws import broadcast_event

# Import all feature enrichment modules
from intel.threat_feeds import threat_feeds
from intel.mitre_tagger import tag_event as mitre_tag
from playbooks.engine import playbook_engine
from honeypot.manager import honeypot_manager
from forensics.memory import forensics_manager
from llm.explainer import alert_explainer
from ueba.baseline import ueba_engine
from gnn.graph_builder import graph_builder

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
    
    Processing pipeline for each event:
      1. AI anomaly scoring (LSTM)
      2. Threat intel IOC check (Bloom filter)
      3. MITRE ATT&CK tagging
      4. Honeypot canary check
      5. UEBA user behavior analysis
      6. GNN lateral movement detection
      7. Automated playbook evaluation
      8. LLM explanation (for high-severity only)
      9. Memory forensics trigger (for critical events)
      10. Audit chain + WebSocket broadcast
    """
    global _recent_events_cache
    results = []

    for event in batch.events:
        event_dict = event.dict()

        # ── Step 1: AI Anomaly Scoring ──────────────────────────
        threat_score = await asyncio.to_thread(score_event, event_dict)
        event_dict["threat_score"] = round(threat_score, 2)
        event_dict["threat_level"] = classify_level(threat_score)

        # ── Step 2: Threat Intel IOC Check ──────────────────────
        ioc_result = threat_feeds.check_event(event_dict)
        event_dict.update(ioc_result)
        
        # IOC match auto-escalates to danger
        if ioc_result["ioc_matched"]:
            event_dict["threat_score"] = max(event_dict["threat_score"], 85.0)
            event_dict["threat_level"] = "danger"

        # ── Step 3: MITRE ATT&CK Tagging ───────────────────────
        mitre_result = mitre_tag(event_dict)
        event_dict.update(mitre_result)

        # ── Step 4: Honeypot Check ──────────────────────────────
        honeypot_result = honeypot_manager.check_event(event_dict)
        event_dict.update(honeypot_result)
        
        # Honeypot hit = guaranteed threat, max score
        if honeypot_result["honeypot_hit"]:
            event_dict["threat_score"] = 100.0
            event_dict["threat_level"] = "danger"

        # ── Step 5: UEBA Analysis ───────────────────────────────
        ueba_result = ueba_engine.process_event(event_dict)
        event_dict.update(ueba_result)

        # ── Step 6: GNN Lateral Movement ────────────────────────
        if event_dict.get("type") == "network_connect" or event_dict.get("port", 0) > 0:
            graph_builder.add_connection(event_dict)
            gnn_result = graph_builder.detect_lateral_movement(event_dict)
            event_dict.update(gnn_result)

        # ── Step 7: Playbook Evaluation ─────────────────────────
        if event_dict["threat_score"] >= 70 or event_dict.get("ioc_matched") or \
           event_dict.get("honeypot_hit"):
            playbook_results = playbook_engine.evaluate_event(event_dict)
            if playbook_results:
                event_dict["playbook_actions"] = playbook_results

        # ── Step 8: LLM Explanation (high-severity only) ────────
        if event_dict["threat_score"] >= 50 and event_dict.get("mitre_technique_count", 0) > 0:
            explanation = await asyncio.to_thread(alert_explainer.explain, event_dict)
            event_dict["explanation"] = explanation.get("explanation", "")
            event_dict["explanation_method"] = explanation.get("method", "")

        # ── Step 9: Memory Forensics (critical events) ──────────
        if event_dict["threat_score"] >= 70:
            trigger = "honeypot" if event_dict.get("honeypot_hit") else \
                      "ioc" if event_dict.get("ioc_matched") else "lstm"
            capture = forensics_manager.trigger_capture(event_dict, trigger)
            if capture.get("captured", capture.get("status") == "completed"):
                event_dict["forensics_capture_id"] = capture.get("capture_id")

        # ── Step 10: Cache, Audit, and Broadcast ────────────────
        _recent_events_cache.insert(0, event_dict)
        if len(_recent_events_cache) > MAX_CACHE_SIZE:
            _recent_events_cache = _recent_events_cache[:MAX_CACHE_SIZE]

        # Save to audit chain if warning or higher
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
        "warnings": sum(1 for r in results if r["threat_level"] == "warning"),
        "ioc_matches": sum(1 for r in results if r.get("ioc_matched")),
        "honeypot_hits": sum(1 for r in results if r.get("honeypot_hit")),
        "mitre_tags": sum(r.get("mitre_technique_count", 0) for r in results),
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
            "max_score": 0,
            "ioc_matches": 0,
            "honeypot_hits": 0,
            "mitre_tags": 0,
        }

    scores = [e.get("threat_score", 0) for e in events]

    return {
        "total_events": len(events),
        "safe_count": sum(1 for e in events if e.get("threat_level") == "safe"),
        "warning_count": sum(1 for e in events if e.get("threat_level") == "warning"),
        "danger_count": sum(1 for e in events if e.get("threat_level") == "danger"),
        "avg_score": round(sum(scores) / len(scores), 2),
        "max_score": round(max(scores), 2),
        "ioc_matches": sum(1 for e in events if e.get("ioc_matched")),
        "honeypot_hits": sum(1 for e in events if e.get("honeypot_hit")),
        "mitre_tags": sum(e.get("mitre_technique_count", 0) for e in events),
    }


@router.get("/events/model-status")
async def model_status():
    """Get the current AI model status."""
    return get_model_status()
