#!/bin/bash
# ═══════════════════════════════════════════════════════
# AEGIS WSL2 Setup Helper
# Sets up the development environment inside WSL2 Ubuntu
# ═══════════════════════════════════════════════════════

set -e

echo "╔══════════════════════════════════════════════╗"
echo "║        AEGIS WSL2 Environment Setup          ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# Step 1: System packages
echo "[1/6] Updating system packages..."
sudo apt-get update -qq && sudo apt-get upgrade -y -qq
echo "  ✓ System updated"
echo ""

# Step 2: eBPF tools
echo "[2/6] Installing eBPF tools..."
sudo apt-get install -y -qq \
    bpfcc-tools \
    python3-bpfcc \
    linux-headers-$(uname -r) \
    python3-pip \
    python3-venv
echo "  ✓ eBPF tools installed"
echo ""

# Step 3: Node.js
echo "[3/6] Installing Node.js 18..."
if ! command -v node &> /dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
    sudo apt-get install -y -qq nodejs
fi
echo "  Node version: $(node --version)"
echo "  npm version: $(npm --version)"
echo ""

# Step 4: snarkjs and circom
echo "[4/6] Installing ZK tools..."
sudo npm install -g snarkjs
if ! command -v circom &> /dev/null; then
    curl -sLo circom https://github.com/iden3/circom/releases/download/v2.1.6/circom-linux-amd64
    chmod +x circom
    sudo mv circom /usr/local/bin/
fi
echo "  snarkjs version: $(snarkjs --version 2>/dev/null || echo 'installed')"
echo "  circom: $(which circom)"
echo ""

# Step 5: Python packages
echo "[5/6] Installing Python packages..."
pip3 install --quiet \
    fastapi uvicorn torch numpy pandas \
    scikit-learn supabase cryptography \
    websockets python-multipart requests \
    python-jose python-dotenv joblib psutil
echo "  ✓ Python packages installed"
echo ""

# Step 6: Docker (optional)
echo "[6/6] Installing Docker..."
if ! command -v docker &> /dev/null; then
    sudo apt-get install -y -qq docker.io
    sudo usermod -aG docker $USER
    echo "  ✓ Docker installed (re-login for group changes)"
else
    echo "  ✓ Docker already installed"
fi
echo ""

echo "═══════════════════════════════════════════════"
echo " AEGIS Environment Ready!"
echo ""
echo " Next steps:"
echo "   1. cd aegis/backend && uvicorn main:app --reload"
echo "   2. cd aegis/agent && sudo python3 agent.py"
echo "   3. cd aegis/frontend && npm install && npm run dev"
echo "═══════════════════════════════════════════════"
