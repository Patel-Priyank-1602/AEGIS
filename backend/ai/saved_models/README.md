# AEGIS Saved Models

This directory contains the **trained LSTM Autoencoder** model files.

## Files

| File | Size | Description |
|---|---|---|
| `lstm_model.pt` | ~504 KB | Trained PyTorch LSTM Autoencoder model |
| `training_log.json` | ~63 KB | 1000-epoch training loss history |

## Model Details

- **Architecture:** LSTM Autoencoder (input=10, hidden=64, 2 layers)
- **Trained on:** Real machine telemetry from `real_agent.py`
- **Data source:** `psutil` kernel-level process & network events
- **Epochs:** 1000 (auto-scaled for 250+ events)
- **Final loss:** ~0.055 (see `training_log.json`)

## How to Retrain on Your Own Data

```bash
# 1. Start the backend
cd backend && uvicorn main:app --reload --port 8000

# 2. Run the real agent to collect genuine OS data
cd agent && python real_agent.py --verbose

# 3. Wait a few minutes, then export collected events
python -c "import urllib.request; urllib.request.urlretrieve('http://localhost:8000/api/events/recent?limit=1000', '../baseline_events.json')"

# 4. Train the model on your data
cd backend && python ai/trainer.py ../baseline_events.json
```

> **Note:** Retrain the model on each deployment machine for best accuracy.
> The model learns YOUR machine's normal behavior, so a model trained on
> one machine may flag normal activity on another machine as anomalous.
