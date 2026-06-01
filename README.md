# AEGIS — Zero-Trust AI Security Platform

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![PyTorch](https://img.shields.io/badge/PyTorch-2.3-EE4C2C?style=for-the-badge&logo=pytorch&logoColor=white)
![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-5.5-3178C6?style=for-the-badge&logo=typescript&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

> **Real-time OS monitoring • AI anomaly detection • ZK-SNARK authentication • Tamper-proof audit chain**

AEGIS watches your operating system at the kernel level using eBPF, learns your normal behavior with an LSTM Autoencoder, detects anomalies in real-time, authenticates users without passwords using Zero-Knowledge proofs, and records every security event in a tamper-proof SHA-256 hash chain.

---

## 🏗️ 4 Domains Combined

| Domain | Technology | What It Does |
|--------|-----------|-------------|
| **Operating System** | eBPF + BCC | Kernel-level monitoring of files, processes, and network |
| **Artificial Intelligence** | PyTorch LSTM Autoencoder | Behavioral anomaly detection trained on YOUR system |
| **Cryptography** | ZK-SNARKs + SHA-256 + AES-256 | Passwordless auth + tamper-proof logs + encrypted storage |
| **Web Technology** | React + FastAPI + WebSocket | Real-time dashboard with live threat visualization |

---

## 🔄 How It Works

```
┌──────────────────┐     JSON events     ┌──────────────────┐     WebSocket     ┌──────────────────┐
│                  │ ──────────────────▶ │                  │ ────────────────▶ │                  │
│   eBPF Agent     │                     │   FastAPI + AI   │                   │  React Dashboard │
│   (Linux kernel) │                     │   (scoring)      │                   │  (live UI)       │
│                  │                     │                  │                   │                  │
└──────────────────┘                     └────────┬─────────┘                   └──────────────────┘
                                                  │
                                          ┌───────▼───────┐
                                          │  Supabase DB  │
                                          │  + Audit Chain│
                                          └───────────────┘
```

1. **Agent** hooks into Linux kernel via eBPF → captures every file open, process exec, network connection
2. **AI Engine** scores each event (0-100) using LSTM Autoencoder trained on your normal behavior
3. **Backend** broadcasts scored events via WebSocket to all connected dashboards
4. **Dashboard** shows live threat feed, animated gauge, and alerts
5. **Audit Chain** records all threats in an encrypted, hash-linked chain that's tamper-proof
6. **ZK Auth** — login without ever sending your password

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| OS Monitor | Python + BCC/eBPF | Kernel-level event capture |
| AI Model | PyTorch LSTM Autoencoder | Behavioral anomaly scoring |
| ZK Proofs | circom + snarkjs | Passwordless authentication |
| Backend | FastAPI + WebSocket | API, scoring, streaming |
| Frontend | React + Vite + TypeScript | Real-time dashboard |
| Database | Supabase (PostgreSQL) | Persistent storage |
| Encryption | AES-256 (Fernet) + SHA-256 | Log encryption + hash chain |
| Deployment | Docker + Render + Netlify | Cloud hosting |

---

## 🚀 Getting Started

### Prerequisites
- WSL2 Ubuntu (for Windows users)
- Python 3.10+
- Node.js 18+
- Git

### Quick Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/aegis.git
cd aegis

# Option 1: Use the setup script (WSL2)
chmod +x scripts/setup_wsl.sh
./scripts/setup_wsl.sh

# Option 2: Manual setup
# Backend
cd backend
pip install -r requirements.txt
cp .env.example .env  # Edit with your values

# Frontend
cd ../frontend
npm install
cp .env.example .env
```

### Run Locally

```bash
# Terminal 1: Backend
cd backend
uvicorn main:app --reload --port 8000

# Terminal 2: eBPF Agent (needs sudo, WSL2/Linux only)
cd agent
sudo python3 agent.py

# Terminal 3: Frontend
cd frontend
npm run dev
```

Open **http://localhost:5173** → Register → See live events!

### Train the AI Model

```bash
# Generate synthetic training data
python3 scripts/train_model.py --generate 500

# Or use real collected data after running the agent
python3 scripts/train_model.py agent/baseline_events.json
```

---

## 📡 API Reference

| Method | Endpoint | Description |
|--------|---------|-------------|
| `GET` | `/` | Health check |
| `GET` | `/health` | AI engine status |
| `POST` | `/api/auth/register` | Register with ZK hash |
| `POST` | `/api/auth/login` | Login with ZK proof |
| `POST` | `/api/events` | Receive OS events (agent) |
| `GET` | `/api/events/recent` | Last 100 events |
| `GET` | `/api/events/stats` | Event statistics |
| `GET` | `/api/audit` | Audit log entries |
| `GET` | `/api/audit/verify/chain` | Verify chain integrity |
| `GET` | `/api/audit/export/json` | Export audit report |
| `WS` | `/ws/events` | Live event stream |

---

## 🔐 Key Features

- **No passwords. Ever.** ZK-SNARK proof authentication
- **OS-level monitoring** using eBPF (same tech as Cloudflare, Meta)
- **AI model trained on YOUR behavior**, not generic rules
- **Tamper-proof audit logs** with SHA-256 hash chain
- **Real-time dashboard** with WebSocket streaming
- **AES-256 encryption** for all stored data
- **Demo mode** — works without a running agent

---

## 📁 Project Structure

```
aegis/
├── agent/                    # eBPF OS monitor (Linux)
│   ├── agent.py              # Main eBPF hook script
│   ├── collector.py          # Event buffering
│   └── sender.py             # HTTP batch sender
├── backend/                  # FastAPI server
│   ├── main.py               # App entry point
│   ├── api/                  # REST + WebSocket routes
│   ├── ai/                   # LSTM Autoencoder engine
│   ├── crypto/               # ZK verify + audit chain + AES
│   ├── db/                   # Supabase client
│   └── core/                 # Config + Pydantic models
├── frontend/                 # React dashboard
│   └── src/
│       ├── pages/            # Login, Dashboard, Audit, Settings
│       ├── components/       # ThreatFeed, ThreatGauge, AlertBanner
│       ├── hooks/            # useWebSocket, useZKAuth
│       └── services/         # API client
├── zk/                       # ZK circuit files
│   └── circuit.circom        # Poseidon hash proof circuit
├── scripts/                  # Setup & training scripts
├── docker-compose.yml        # Full stack deployment
└── README.md
```

---

## 🐳 Docker Deployment

```bash
# Build and run everything
docker-compose up --build

# Or deploy separately:
# Backend → Render (render.com)
# Frontend → Netlify (netlify.com)
```

---

## 📄 License

MIT License — Built for learning, research, and portfolio.

---

**Built with:** Python · PyTorch · circom · snarkjs · FastAPI · React · Supabase · eBPF  
**Cost:** ₹0 | **Domains:** 4 | **Architecture:** Zero-Trust
