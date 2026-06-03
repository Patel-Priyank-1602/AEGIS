"""
AEGIS Advanced Features API
Routes for all 10 security features: threat intel, MITRE tagging,
playbooks, honeypots, forensics, LLM explanations, UEBA, GNN,
federated learning, and post-quantum crypto.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List

# Import all feature modules
from intel.threat_feeds import threat_feeds
from intel.mitre_tagger import tag_event, get_technique_info, get_coverage_matrix
from playbooks.engine import playbook_engine, PLAYBOOKS
from honeypot.manager import honeypot_manager
from forensics.memory import forensics_manager
from llm.explainer import alert_explainer
from ueba.baseline import ueba_engine
from gnn.graph_builder import graph_builder
from federated.server import fed_server
from crypto.pqc import pqc_manager

router = APIRouter()


# ─── Request Models ─────────────────────────────────────────────
class IOCAddRequest(BaseModel):
    ioc_type: str  # ip, domain, hash, url
    value: str
    critical: bool = False


class FedClientRegister(BaseModel):
    client_id: str
    metadata: dict = {}


class FedGradientUpload(BaseModel):
    client_id: str
    gradients: dict


# ─── Threat Intelligence ────────────────────────────────────────
@router.get("/threat-intel/stats")
async def threat_intel_stats():
    """Get threat intelligence feed statistics."""
    return threat_feeds.get_stats()


@router.post("/threat-intel/refresh")
async def refresh_threat_feeds():
    """Manually trigger a threat feed refresh."""
    import asyncio
    await asyncio.to_thread(threat_feeds.refresh_all_feeds)
    return threat_feeds.get_stats()


@router.post("/threat-intel/add-ioc")
async def add_custom_ioc(req: IOCAddRequest):
    """Add a custom IOC to the threat database."""
    threat_feeds.add_custom_ioc(req.ioc_type, req.value, req.critical)
    return {"added": True, "type": req.ioc_type, "value": req.value}


@router.get("/threat-intel/check/{ip}")
async def check_ip(ip: str):
    """Check if an IP is in the threat intelligence database."""
    result = threat_feeds.check_event({"ip": ip})
    return result


# ─── MITRE ATT&CK ───────────────────────────────────────────────
@router.get("/mitre/coverage")
async def mitre_coverage():
    """Get MITRE ATT&CK coverage matrix — which tactics AEGIS detects."""
    return get_coverage_matrix()


@router.get("/mitre/technique/{technique_id}")
async def mitre_technique(technique_id: str):
    """Get details for a specific MITRE ATT&CK technique."""
    return get_technique_info(technique_id)


# ─── Playbooks ──────────────────────────────────────────────────
@router.get("/playbooks")
async def list_playbooks():
    """List all available playbooks and their configurations."""
    return {
        "playbooks": PLAYBOOKS,
        "stats": playbook_engine.get_stats(),
    }


@router.get("/playbooks/executions")
async def playbook_executions(limit: int = 50):
    """Get recent playbook execution history."""
    return {
        "executions": playbook_engine.get_executions(limit),
        "total": len(playbook_engine.execution_log),
    }


@router.post("/playbooks/undo/{action_id}")
async def undo_action(action_id: str):
    """Undo a specific automated response action."""
    result = playbook_engine.ledger.undo(action_id)
    if not result["success"]:
        raise HTTPException(status_code=404, detail=result["message"])
    return result


@router.post("/playbooks/toggle")
async def toggle_playbooks(enabled: bool = True):
    """Enable or disable automated playbook execution."""
    playbook_engine.enabled = enabled
    return {"enabled": playbook_engine.enabled}


# ─── Honeypot ───────────────────────────────────────────────────
@router.get("/honeypot/stats")
async def honeypot_stats():
    """Get honeypot deployment and alert statistics."""
    return honeypot_manager.get_stats()


@router.get("/honeypot/alerts")
async def honeypot_alerts(limit: int = 50):
    """Get recent honeypot intrusion alerts."""
    return {
        "alerts": honeypot_manager.get_alerts(limit),
        "total_hits": honeypot_manager.total_hits,
    }


@router.get("/honeypot/resources")
async def honeypot_resources():
    """Get list of deployed honeypot resources."""
    return honeypot_manager.get_deployed_resources()


# ─── Memory Forensics ───────────────────────────────────────────
@router.get("/forensics/stats")
async def forensics_stats():
    """Get memory forensics statistics."""
    return forensics_manager.get_stats()


@router.get("/forensics/captures")
async def forensics_captures(limit: int = 20):
    """Get recent memory forensics captures."""
    return {
        "captures": forensics_manager.get_captures(limit),
        "total": forensics_manager.total_captures,
    }


@router.get("/forensics/capture/{capture_id}")
async def get_capture(capture_id: str):
    """Get details of a specific memory capture."""
    capture = forensics_manager.get_capture(capture_id)
    if not capture:
        raise HTTPException(status_code=404, detail="Capture not found")
    return capture


# ─── LLM Alert Explainer ────────────────────────────────────────
@router.get("/explainer/stats")
async def explainer_stats():
    """Get LLM explainer statistics."""
    return alert_explainer.get_stats()


@router.post("/explain")
async def explain_alert(event: dict):
    """Generate an LLM explanation for a security alert."""
    return alert_explainer.explain(event)


# ─── UEBA ───────────────────────────────────────────────────────
@router.get("/ueba/stats")
async def ueba_stats():
    """Get UEBA engine statistics."""
    return ueba_engine.get_stats()


@router.get("/ueba/profiles")
async def ueba_profiles():
    """Get all user behavioral profiles sorted by risk."""
    return {"profiles": ueba_engine.get_all_profiles()}


@router.get("/ueba/profile/{user_id}")
async def ueba_profile(user_id: str):
    """Get behavioral profile for a specific user."""
    profile = ueba_engine.get_user_profile(user_id)
    if not profile:
        raise HTTPException(status_code=404, detail="User profile not found")
    return profile


@router.get("/ueba/risky-users")
async def ueba_risky_users(min_score: float = 30.0):
    """Get users with risk scores above threshold."""
    return {"users": ueba_engine.get_risky_users(min_score)}


# ─── GNN / Network Graph ────────────────────────────────────────
@router.get("/graph/snapshot")
async def graph_snapshot():
    """Get current network graph state for visualization."""
    return graph_builder.get_graph_snapshot()


@router.get("/graph/stats")
async def graph_stats():
    """Get network graph statistics."""
    return graph_builder.get_stats()


@router.get("/graph/alerts")
async def graph_alerts(limit: int = 50):
    """Get lateral movement detection alerts."""
    return {
        "alerts": graph_builder.get_alerts(limit),
        "total": len(graph_builder.alerts),
    }


# ─── Federated Learning ─────────────────────────────────────────
@router.get("/federated/stats")
async def fed_stats():
    """Get federated learning server statistics."""
    return fed_server.get_stats()


@router.post("/federated/register")
async def fed_register(req: FedClientRegister):
    """Register a new federated learning client."""
    return fed_server.register_client(req.client_id, req.metadata)


@router.post("/federated/upload")
async def fed_upload(req: FedGradientUpload):
    """Upload model gradients from a client."""
    return fed_server.upload_gradients(req.client_id, req.gradients)


@router.get("/federated/model")
async def fed_model():
    """Get the current global model version."""
    return fed_server.get_global_model()


# ─── Post-Quantum Cryptography ──────────────────────────────────
@router.get("/pqc/stats")
async def pqc_stats():
    """Get post-quantum cryptography statistics."""
    return pqc_manager.get_stats()


@router.get("/pqc/public-key")
async def pqc_public_key():
    """Get the Dilithium public key for verification."""
    return {
        "algorithm": pqc_manager.dilithium_keypair["algorithm"],
        "public_key": pqc_manager.dilithium_keypair["public_key"],
    }


@router.post("/pqc/key-exchange")
async def pqc_key_exchange():
    """Perform a Kyber key encapsulation."""
    ciphertext, shared_secret = pqc_manager.kyber_encapsulate()
    return {
        "ciphertext": ciphertext,
        "algorithm": pqc_manager.kyber_keypair["algorithm"],
    }


# ─── Unified Status Endpoint ────────────────────────────────────
@router.get("/features/status")
async def features_status():
    """Get status of all 10 advanced features."""
    return {
        "threat_intel": threat_feeds.get_stats(),
        "mitre_attack": {"techniques_loaded": len(get_coverage_matrix())},
        "playbooks": playbook_engine.get_stats(),
        "honeypot": honeypot_manager.get_stats(),
        "forensics": forensics_manager.get_stats(),
        "llm_explainer": alert_explainer.get_stats(),
        "ueba": ueba_engine.get_stats(),
        "gnn_graph": graph_builder.get_stats(),
        "federated": fed_server.get_stats(),
        "pqc": pqc_manager.get_stats(),
    }
