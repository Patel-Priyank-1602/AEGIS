from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime
from enum import Enum


class ThreatLevel(str, Enum):
    SAFE = "safe"
    WARNING = "warning"
    DANGER = "danger"


# ─── Event Models ───────────────────────────────────────────────
class OSEvent(BaseModel):
    """Raw OS event received from the eBPF agent."""
    pid: int
    process: str
    file: str = ""
    timestamp: str
    type: str = "file_open"
    ip: str = "127.0.0.1"
    port: int = 0


class EventBatch(BaseModel):
    """Batch of OS events sent by the agent."""
    events: List[OSEvent]


class ScoredEvent(BaseModel):
    """Event after AI scoring."""
    pid: int
    process: str
    file: str = ""
    timestamp: str
    type: str = "file_open"
    ip: str = "127.0.0.1"
    port: int = 0
    threat_score: float = 0.0
    threat_level: ThreatLevel = ThreatLevel.SAFE


# ─── Auth Models ────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    public_hash: str = Field(..., description="Poseidon hash of user's secret")


class LoginRequest(BaseModel):
    username: str
    proof: dict = Field(..., description="ZK-SNARK proof object")
    public_signals: list = Field(..., description="Public signals from proof")


class AuthResponse(BaseModel):
    token: str
    message: str
    username: str


# ─── Audit Models ───────────────────────────────────────────────
class AuditEntry(BaseModel):
    id: Optional[str] = None
    hash: str
    previous_hash: str
    encrypted_content: str
    threat_level: str
    created_at: str


class AuditVerification(BaseModel):
    is_valid: bool
    total_entries: int
    broken_at: Optional[int] = None
    message: str


# ─── Stats Models ───────────────────────────────────────────────
class EventStats(BaseModel):
    total_events: int = 0
    safe_count: int = 0
    warning_count: int = 0
    danger_count: int = 0
    avg_score: float = 0.0
    max_score: float = 0.0
