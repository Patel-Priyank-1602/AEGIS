# AEGIS Saved Models

This directory contains trained LSTM Autoencoder model files.

## Files
- `lstm_model.pt` — Trained PyTorch model (generated after training)
- `training_log.json` — Training metrics and loss history

## How to Generate

```bash
# Generate synthetic training data and train
python3 scripts/train_model.py --generate 500

# Or train on real agent-collected data
python3 scripts/train_model.py agent/baseline_events.json
```

> **Note:** Model files are excluded from git via `.gitignore`.
> Each deployment should train its own model on local behavior.
