# AEGIS v2.0 Setup & Testing Guide

This guide covers everything you need to install, configure, and test all 10 advanced features of the AEGIS v2.0 security platform.

---

## 📦 1. Dependencies & Packages to Install

### Backend (Python)
You must install the core dependencies plus the new libraries required for the v2.0 features (Playbooks and GNN Lateral Movement).

Open a terminal in the `backend/` folder and run:
```bash
# 1. Install base requirements
pip install -r requirements.txt

# 2. Install the new v2.0 specific libraries
pip install APScheduler networkx
```

*(Optional libraries for full native support)*:
- If you want the Post-Quantum Cryptography to run mathematically real Dilithium/Kyber instead of simulated, install `liboqs-python` (Requires a C compiler).
- If you want native Memory Forensics YARA scanning on Linux, install `yara-python`.

### Frontend (React/Node)
Open a terminal in the `frontend/` folder and run:
```bash
npm install
```

---

## 🧠 2. AI Models to Setup / Train

AEGIS v2.0 uses two distinct AI architectures that need to be prepared:

### A. The LSTM Anomaly Detection Model (PyTorch)
The core engine needs to learn your machine's baseline behavior.
1. Start the backend: `uvicorn main:app --reload`
2. Start the telemetry simulator: `python agent/agent_sim.py`
3. Open a new terminal in `backend/` and download the baseline data:
   ```bash
   python -c "import urllib.request; urllib.request.urlretrieve('http://localhost:8000/api/events/recent?limit=1000', '../baseline_events.json')"
   ```
4. Train the PyTorch model:
   ```bash
   python ai/trainer.py ../baseline_events.json
   ```
   *This saves `lstm_model.pt` in `backend/ai/saved_models/`.*

### B. The LLM Alert Explainer (Ollama RAG)
Feature #6 uses a local LLM to generate plain-English explanations for alerts. It is designed to use **Ollama** so data never leaves your machine.
1. Download and install [Ollama](https://ollama.com/).
2. Open a terminal and pull the Qwen 2.5 Coder model:
   ```bash
   ollama run qwen2.5-coder:7b
   ```
*(Note: If Ollama is not running on port 11434, AEGIS gracefully falls back to a high-speed template-matching explainer engine, so the app will not crash).*

---

## 🚀 3. How to Boot the System

Start both servers in separate terminal windows:

**Terminal 1 (Backend):**
```bash
cd backend
uvicorn main:app --reload --port 8000
```

**Terminal 2 (Frontend):**
```bash
cd frontend
npm run dev
```

Navigate to **http://localhost:5173** in your browser. Log in using any username/password (it will automatically generate a Zero-Knowledge proof and register you if it's your first time).

---

## 🎮 4. How to Test the 10 Features Perfectly

Once you are logged into the dashboard, here is exactly how to test the new features:

### The Live Event Dashboard
- **Turn on Demo Mode**: On the main Dashboard, click the **"Demo Mode"** button in the top right. This starts an internal simulator that generates fake system events.
- **Watch the Enrichment Pipeline**: You will see events stream in. Watch closely for high-severity (red) events. You will see:
  - Yellow **MITRE ATT&CK Badges** (e.g., T1095).
  - Red **IOC Badges** indicating a match in the Threat Intel feed.
  - Pink **🍯 TRAP Badges** indicating a honeypot decoy was accessed.
  - An **LLM Explanation paragraph** injected at the bottom of the event card.

### Threat Intel Hub
- Navigate to the **Threat Intel** page on the sidebar.
- You will see live statistics of the Bloom filter loaded with `abuse.ch` data.
- **Test it**: Type `45.33.32.156` into the *Check IP* box and hit Check. You will see it immediately flag as a Critical C2 server match.
- Use the form on the right to manually add your own custom IP or Domain to the blocklist.

### Automated Playbooks
- Navigate to the **Playbooks** page on the sidebar.
- The right side shows an audit log of all "Automated Actions" (like Isolating Hosts or Blocking IPs) that the backend triggered.
- **Test it**: Find an action in the execution log and click the **Undo** button. The Action Ledger will mathematically reverse the command payload!

### The Command Hub (All Features)
- Navigate to the **All Features** page.
- This is the master overview. You can see the live statistics of:
  - The **GNN** (Graph Neural Network) mapping nodes and edges for Lateral Movement.
  - The **UEBA** profiling engine tracking user behavior.
  - The **Federated Learning** server aggregating training rounds with Differential Privacy (ε=0.1).
  - The **Post-Quantum Cryptography** engine generating Dilithium signatures.
