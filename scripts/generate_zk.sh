#!/bin/bash
# ═══════════════════════════════════════════════════════
# AEGIS ZK Circuit Compilation Script
# Compiles the circom circuit and generates proving keys
# ═══════════════════════════════════════════════════════

set -e

echo "╔══════════════════════════════════════════════╗"
echo "║       AEGIS ZK Circuit Generator             ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

cd "$(dirname "$0")/../zk"

# Step 1: Install circomlib
echo "[1/5] Installing circomlib..."
npm install circomlib
echo "  ✓ circomlib installed"
echo ""

# Step 2: Compile the circuit
echo "[2/5] Compiling circuit..."
circom circuit.circom --r1cs --wasm --sym -o .
echo "  ✓ Circuit compiled"
echo "  ✓ Generated: circuit.r1cs, circuit_js/circuit.wasm"
echo ""

# Step 3: Download trusted setup (Powers of Tau ceremony)
echo "[3/5] Downloading Powers of Tau..."
if [ ! -f "powersOfTau28_hez_final_12.ptau" ]; then
    wget -q https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_12.ptau
    echo "  ✓ Downloaded trusted setup"
else
    echo "  ✓ Trusted setup already exists"
fi
echo ""

# Step 4: Generate proving key
echo "[4/5] Generating proving key..."
snarkjs groth16 setup circuit.r1cs powersOfTau28_hez_final_12.ptau circuit_0000.zkey
echo "  Entropy contribution..."
snarkjs zkey contribute circuit_0000.zkey circuit_final.zkey \
    --name="AEGIS-$(date +%s)" -v -e="$(head -c 64 /dev/urandom | xxd -p)"
echo "  ✓ Proving key generated"
echo ""

# Step 5: Export verification key
echo "[5/5] Exporting verification key..."
snarkjs zkey export verificationkey circuit_final.zkey verification_key.json
echo "  ✓ Verification key exported"
echo ""

# Copy WASM to frontend public directory
echo "Copying circuit files for frontend..."
mkdir -p ../frontend/public/zk
cp circuit_js/circuit.wasm ../frontend/public/zk/circuit.wasm
cp circuit_final.zkey ../frontend/public/zk/circuit_final.zkey
echo "  ✓ Files copied to frontend/public/zk/"
echo ""

# Cleanup
rm -f circuit_0000.zkey

echo "═══════════════════════════════════════════════"
echo " ZK Circuit Ready!"
echo " Verification key: zk/verification_key.json"
echo " Circuit WASM:     zk/circuit_js/circuit.wasm"
echo " Proving key:      zk/circuit_final.zkey"
echo "═══════════════════════════════════════════════"
