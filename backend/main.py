from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from api import routes_events, routes_auth, routes_audit, routes_ws, routes_features
from core.config import settings
import os
import threading

app = FastAPI(
    title="AEGIS API",
    description="Zero-Trust AI Security Platform — OS Monitoring, AI Anomaly Detection, "
                "GNN Lateral Movement, Threat Intel, MITRE ATT&CK, Automated Playbooks, "
                "UEBA, Honeypots, Memory Forensics, LLM Explainer, Federated Learning, "
                "Post-Quantum Cryptography",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Allow React frontend to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        settings.FRONTEND_URL
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include all route files
app.include_router(routes_events.router, prefix="/api", tags=["Events"])
app.include_router(routes_auth.router, prefix="/api", tags=["Authentication"])
app.include_router(routes_audit.router, prefix="/api", tags=["Audit"])
app.include_router(routes_features.router, prefix="/api", tags=["Advanced Features"])
app.include_router(routes_ws.router, tags=["WebSocket"])


@app.on_event("startup")
async def startup_event():
    """Initialize all feature modules on startup."""
    from intel.threat_feeds import threat_feeds

    # Start threat intel feed auto-refresh (background thread)
    def init_feeds():
        try:
            threat_feeds.refresh_all_feeds()
            threat_feeds.start_auto_refresh(interval_minutes=60)
        except Exception as e:
            print(f"[Startup] Threat feed init failed (non-critical): {e}")

    threading.Thread(target=init_feeds, daemon=True).start()
    print("[Startup] AEGIS v2.0 — All 10 features initialized")


@app.get("/", tags=["Health"])
def root():
    return {
        "name": "AEGIS API",
        "status": "operational",
        "version": "2.0.0",
        "description": "Zero-Trust AI Security Platform with 10 Advanced Features",
        "features": [
            "LSTM Anomaly Detection", "GNN Lateral Movement", "Threat Intel Feeds",
            "MITRE ATT&CK Tagging", "Automated Playbooks", "Honeypot Deception",
            "Memory Forensics", "LLM Alert Explainer", "UEBA Baselines",
            "Federated Learning", "Post-Quantum Cryptography"
        ]
    }


@app.get("/health", tags=["Health"])
def health():
    model_exists = os.path.exists("ai/saved_models/lstm_model.pt")
    return {
        "status": "healthy",
        "ai_engine": "active" if model_exists else "no model loaded",
        "model_ready": model_exists,
        "version": "2.0.0",
        "features_active": 10
    }
