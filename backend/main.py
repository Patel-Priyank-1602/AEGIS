from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from api import routes_events, routes_auth, routes_audit, routes_ws
from core.config import settings
import os

app = FastAPI(
    title="AEGIS API",
    description="Zero-Trust AI Security Platform — OS Monitoring, AI Anomaly Detection, ZK Authentication",
    version="1.0.0",
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
app.include_router(routes_ws.router, tags=["WebSocket"])


@app.get("/", tags=["Health"])
def root():
    return {
        "name": "AEGIS API",
        "status": "operational",
        "version": "1.0.0",
        "description": "Zero-Trust AI Security Platform"
    }


@app.get("/health", tags=["Health"])
def health():
    model_exists = os.path.exists("ai/saved_models/lstm_model.pt")
    return {
        "status": "healthy",
        "ai_engine": "active" if model_exists else "no model loaded",
        "model_ready": model_exists
    }
