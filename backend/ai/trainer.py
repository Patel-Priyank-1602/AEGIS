"""
AEGIS Model Trainer
Trains the LSTM Autoencoder on baseline (normal) system behavior data.
The model learns to perfectly reconstruct normal event sequences.
When deployed, events it cannot reconstruct well are flagged as anomalous.
"""

import torch
import torch.nn as nn
import numpy as np
import json
import os
from datetime import datetime
from ai.model import LSTMAutoencoder
from ai.features import event_to_features

# ─── Training Configuration ────────────────────────────────────
SEQUENCE_LENGTH = 20    # Number of events per sequence window
EPOCHS = 100            # Training iterations (more = better convergence)
BATCH_SIZE = 32         # Sequences per batch
LEARNING_RATE = 0.001   # Adam optimizer learning rate
BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..")
MODEL_DIR = os.path.join(BACKEND_DIR, "ai", "saved_models")
MODEL_PATH = os.path.join(MODEL_DIR, "lstm_model.pt")
TRAINING_LOG_PATH = os.path.join(MODEL_DIR, "training_log.json")


def create_sequences(features: np.ndarray, seq_len: int = SEQUENCE_LENGTH) -> np.ndarray:
    """
    Convert flat array of feature vectors into overlapping sliding window sequences.
    
    Example with seq_len=3:
        Input:  [f0, f1, f2, f3, f4]
        Output: [[f0,f1,f2], [f1,f2,f3], [f2,f3,f4]]
    """
    sequences = []
    for i in range(len(features) - seq_len):
        seq = features[i:i + seq_len]
        sequences.append(seq)
    return np.array(sequences)


def train(events_list: list, epochs: int = EPOCHS, save: bool = True) -> dict:
    """
    Train the LSTM Autoencoder on a list of normal baseline events.
    
    Args:
        events_list: List of event dictionaries (normal behavior data)
        epochs: Number of training epochs
        save: Whether to save the trained model
    
    Returns:
        Dictionary with training metrics
    """
    print(f"╔══════════════════════════════════════════════╗")
    print(f"║         AEGIS AI Model Training              ║")
    print(f"╚══════════════════════════════════════════════╝")
    print(f"  Events: {len(events_list)}")
    print(f"  Sequence Length: {SEQUENCE_LENGTH}")
    print(f"  Epochs: {epochs}")
    print()

    # Step 1: Convert events to feature vectors
    print("[1/4] Converting events to feature vectors...")
    features = np.array([event_to_features(e) for e in events_list], dtype=np.float32)
    print(f"  Feature matrix shape: {features.shape}")

    # Step 2: Create overlapping sequences
    print("[2/4] Creating training sequences...")
    sequences = create_sequences(features)
    X = torch.tensor(sequences, dtype=torch.float32)
    print(f"  Training sequences: {len(sequences)}")

    if len(sequences) < 10:
        print("  ⚠ Too few sequences. Need at least 30 events for meaningful training.")
        return {"error": "insufficient data"}

    # Step 3: Build and train model
    print("[3/4] Training LSTM Autoencoder...")
    model = LSTMAutoencoder(input_size=10, hidden_size=64, num_layers=2)
    optimizer = torch.optim.Adam(model.parameters(), lr=LEARNING_RATE)
    scheduler = torch.optim.lr_scheduler.StepLR(optimizer, step_size=30, gamma=0.5)
    criterion = nn.MSELoss()

    training_log = []
    model.train()

    for epoch in range(epochs):
        total_loss = 0
        batches = 0

        # Mini-batch training
        indices = torch.randperm(len(X))
        for i in range(0, len(X), BATCH_SIZE):
            batch_idx = indices[i:i + BATCH_SIZE]
            batch = X[batch_idx]

            optimizer.zero_grad()
            output = model(batch)
            loss = criterion(output, batch)
            loss.backward()
            optimizer.step()

            total_loss += loss.item()
            batches += 1

        avg_loss = total_loss / batches
        training_log.append({"epoch": epoch + 1, "loss": avg_loss})

        if (epoch + 1) % 10 == 0 or epoch == 0:
            lr = optimizer.param_groups[0]['lr']
            bar = "█" * int(avg_loss * 50)
            print(f"  Epoch {epoch+1:3d}/{epochs} │ Loss: {avg_loss:.6f} │ LR: {lr:.6f} │ {bar}")

        scheduler.step()

    # Step 4: Save model
    if save:
        print("[4/4] Saving model...")
        os.makedirs(MODEL_DIR, exist_ok=True)
        torch.save({
            "model_state_dict": model.state_dict(),
            "input_size": 10,
            "hidden_size": 64,
            "num_layers": 2,
            "trained_at": datetime.utcnow().isoformat(),
            "total_events": len(events_list),
            "total_sequences": len(sequences),
            "final_loss": training_log[-1]["loss"]
        }, MODEL_PATH)

        with open(TRAINING_LOG_PATH, "w") as f:
            json.dump(training_log, f, indent=2)

        print(f"  ✓ Model saved to {MODEL_PATH}")
        print(f"  ✓ Training log saved to {TRAINING_LOG_PATH}")

    final_loss = training_log[-1]["loss"]
    print(f"\n  ═══ Training Complete ═══")
    print(f"  Final Loss: {final_loss:.6f}")
    print(f"  Model Size: {sum(p.numel() for p in model.parameters())} parameters")

    return {
        "final_loss": final_loss,
        "epochs": epochs,
        "sequences": len(sequences),
        "model_path": MODEL_PATH
    }


if __name__ == "__main__":
    # Load baseline events from JSON file
    import sys

    data_file = sys.argv[1] if len(sys.argv) > 1 else "baseline_events.json"

    if not os.path.exists(data_file):
        print(f"Error: {data_file} not found.")
        print("Run the agent first to collect baseline data, then train.")
        print("Usage: python3 trainer.py <path_to_events.json>")
        sys.exit(1)

    with open(data_file) as f:
        events = json.load(f)

    train(events)
