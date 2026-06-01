"""
AEGIS Authentication API
Handles user registration and login using Zero-Knowledge proofs.
The user's secret never touches the server — only mathematical proofs are verified.
"""

from fastapi import APIRouter, HTTPException, Depends
from core.models import RegisterRequest, LoginRequest, AuthResponse
from crypto.zk_verifier import verify_proof, compute_public_hash
from db.supabase_client import db
import secrets
import hashlib

router = APIRouter()


@router.post("/auth/register", response_model=AuthResponse)
async def register(req: RegisterRequest):
    """
    Register a new user with their ZK public hash.
    The secret never arrives here — only its hash, computed in the browser.
    """
    # Check if username already exists
    existing = db.select("users", filters={"username": req.username})
    if existing:
        raise HTTPException(
            status_code=400,
            detail="Username already exists. Choose a different one."
        )

    # Store username and public hash
    db.insert("users", {
        "username": req.username,
        "public_hash": req.public_hash
    })

    # Create initial session token
    token = secrets.token_hex(32)
    db.insert("sessions", {
        "username": req.username,
        "token": token
    })

    return AuthResponse(
        token=token,
        message="Registration successful. ZK identity created.",
        username=req.username
    )


@router.post("/auth/login", response_model=AuthResponse)
async def login(req: LoginRequest):
    """
    Authenticate using a ZK-SNARK proof.
    The user proves they know the secret without transmitting it.
    
    Flow:
        1. User enters secret in browser
        2. Browser generates ZK proof locally (secret never leaves)
        3. Only the proof is sent to this endpoint
        4. We verify the proof mathematically
        5. If valid, session token is issued
    """
    # Find user
    users = db.select("users", filters={"username": req.username})
    if not users:
        raise HTTPException(status_code=404, detail="User not found")

    user = users[0]

    # Verify the mathematical proof
    is_valid = verify_proof(req.proof, req.public_signals)

    if not is_valid:
        raise HTTPException(
            status_code=401,
            detail="Invalid ZK proof. Authentication failed."
        )

    # Invalidate any existing sessions for this user
    db.delete("sessions", filters={"username": req.username})

    # Generate new session token
    token = secrets.token_hex(32)
    db.insert("sessions", {
        "username": req.username,
        "token": token
    })

    return AuthResponse(
        token=token,
        message="Authenticated via ZK proof. No password transmitted.",
        username=req.username
    )


@router.post("/auth/logout")
async def logout(token: str):
    """End a user's session."""
    deleted = db.delete("sessions", filters={"token": token})
    if deleted == 0:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"message": "Logged out successfully"}


@router.get("/auth/verify-session")
async def verify_session(token: str):
    """Check if a session token is still valid."""
    sessions = db.select("sessions", filters={"token": token})
    if not sessions:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    return {
        "valid": True,
        "username": sessions[0].get("username")
    }


@router.post("/auth/hash")
async def get_hash(secret: str):
    """
    Development helper: compute the public hash for a secret.
    In production, this is done entirely in the browser.
    """
    public_hash = compute_public_hash(secret)
    return {"public_hash": public_hash}
