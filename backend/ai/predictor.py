"""
AEGIS Real-Time Predictor
Loads the trained LSTM model and scores incoming events in real-time.
Falls back to a rule-based scoring system if no model is available.
"""

import torch
import numpy as np
import os
from collections import deque
from ai.features import event_to_features
from ai.model import LSTMAutoencoder
from core.config import settings

# ─── Global State ───────────────────────────────────────────────
_model: LSTMAutoencoder = None
_event_buffer: deque = deque(maxlen=20)  # Rolling window of recent events
_model_loaded: bool = False
_baseline_mse: float = 0.015  # Default baseline; overridden from checkpoint

SEQUENCE_LENGTH = 20


def _load_model():
    """Lazy-load the trained model on first prediction."""
    global _model, _model_loaded, _baseline_mse

    model_path = settings.MODEL_PATH
    if not os.path.exists(model_path):
        print(f"[Predictor] No model found at {model_path}. Using rule-based scoring.")
        _model_loaded = False
        return

    try:
        checkpoint = torch.load(model_path, map_location="cpu", weights_only=False)
        _model = LSTMAutoencoder(
            input_size=checkpoint.get("input_size", 10),
            hidden_size=checkpoint.get("hidden_size", 64),
            num_layers=checkpoint.get("num_layers", 2)
        )
        _model.load_state_dict(checkpoint["model_state_dict"])
        _model.eval()
        _model_loaded = True
        _baseline_mse = checkpoint.get("final_loss", 0.015)
        print(f"[Predictor] Model loaded successfully. Trained at: {checkpoint.get('trained_at', 'unknown')}")
        print(f"[Predictor] Baseline MSE: {_baseline_mse:.6f}")
    except Exception as e:
        print(f"[Predictor] Failed to load model: {e}")
        _model_loaded = False


def score_event(event: dict) -> float:
    """
    Score a single event using HYBRID scoring (AI + rules combined).
    
    The AI model detects anomalies it hasn't seen in training, but it can
    overreact to unfamiliar-but-benign processes (like curl, bash).
    The rule-based scorer provides domain expertise about what's truly dangerous.
    
    By blending both, we get the best of both worlds:
      - Normal events: both agree → low score (safe)
      - Warning events: AI overreacts, rules moderate → medium score (warning)
      - Attack events: both agree → high score (danger)
    """
    global _model, _model_loaded

    # Lazy load model on first call
    if _model is None and not _model_loaded:
        _load_model()

    # Convert event to features
    features = event_to_features(event)
    
    # Always compute the rule-based score (domain knowledge)
    rule_score = _rule_based_score(event, features)
    
    # Create a temporary sequence ending with the current event
    current_sequence = list(_event_buffer)
    current_sequence.append(features)

    # If we have a trained model AND enough context, blend AI + rules
    if _model_loaded and len(current_sequence) >= SEQUENCE_LENGTH:
        ai_score = _ai_score(current_sequence)
        # Hybrid blend: 40% AI (anomaly detection) + 60% rules (domain knowledge)
        # This prevents the AI from over-scoring unfamiliar but benign events
        score = 0.4 * ai_score + 0.6 * rule_score
    else:
        # Before the AI buffer fills, use pure rule-based scoring
        score = rule_score

    # Only add non-threatening events to the permanent buffer
    if score < 60:
        _event_buffer.append(features)

    return round(score, 2)


def _ai_score(sequence: list) -> float:
    """Score using the trained LSTM Autoencoder."""
    try:
        # Create sequence from the provided list
        seq_array = np.array(sequence, dtype=np.float32)
        seq_array = seq_array[-SEQUENCE_LENGTH:]  # Take exactly N events
        x = torch.tensor(seq_array, dtype=torch.float32).unsqueeze(0)  # Add batch dim

        score = _model.anomaly_score(x, baseline_mse=_baseline_mse)
        return score
    except Exception as e:
        print(f"[Predictor] AI scoring error: {e}")
        return 0.0


def _rule_based_score(event: dict, features: list) -> float:
    """
    Fallback rule-based scoring when no AI model is available.
    Uses the feature vector to compute a weighted threat score.
    
    Scoring philosophy:
      - Known good process + normal file = ~0-10 (safe)
      - Ambiguous process (curl/bash) + system path = ~20-45 (warning)
      - Malicious tool + sensitive file + external IP = ~70-100 (danger)
    """
    weights = [
        45.0,   # suspicious process (1.0=malicious→45, 0.3=ambiguous→13.5)
        -15.0,  # known good process (reduces score significantly)
        25.0,   # sensitive file access (/etc/shadow, etc.)
        14.0,   # system path access (/etc/, /proc/, etc.)
        15.0,   # suspicious port (4444, 1337, etc.)
        5.0,    # unusual hour (less weight — not definitive)
        14.0,   # external IP (non-private)
        0.0,    # normalized hour (not used in rules)
        0.0,    # normalized port (not used in rules)
        -3.0,   # file depth (deeper = more normal = lower score)
    ]

    score = sum(f * w for f, w in zip(features, weights))
    # Clamp to 0-100
    score = max(0.0, min(100.0, score))
    return round(score, 2)


def get_model_status() -> dict:
    """Return current model status for health checks."""
    return {
        "model_loaded": _model_loaded,
        "buffer_size": len(_event_buffer),
        "buffer_capacity": SEQUENCE_LENGTH,
        "scoring_mode": "ai" if _model_loaded else "rule_based"
    }
