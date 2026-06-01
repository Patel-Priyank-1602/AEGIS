pragma circom 2.0.0;

include "node_modules/circomlib/circuits/poseidon.circom";

/*
 * AEGIS ZK Authentication Circuit
 * 
 * Purpose: Prove knowledge of a secret without revealing it.
 * 
 * This circuit proves:
 *   "I know a secret S such that Poseidon_hash(S) == publicHash"
 * 
 * The verifier (AEGIS backend) only sees the publicHash and the proof.
 * They NEVER see the secret S itself.
 * 
 * How it works:
 *   1. User enters their secret phrase in the browser
 *   2. Browser converts the phrase to a field element
 *   3. Browser runs this circuit locally to generate a proof
 *   4. Only the proof is sent to the server
 *   5. Server verifies the proof matches the stored publicHash
 *   6. If valid → user is authenticated. Secret never transmitted.
 */
template SecretProof() {
    // ─── Private Input ─────────────────────────────────────────
    // The user's secret. Only they know this.
    // This value NEVER leaves the browser.
    signal input secret;

    // ─── Public Input ──────────────────────────────────────────
    // The hash of the secret, stored on the server during registration.
    // This is public — anyone can see it, but they can't reverse it.
    signal input publicHash;

    // ─── Hash Computation ──────────────────────────────────────
    // Poseidon is a ZK-friendly hash function (much faster than SHA-256
    // inside a ZK circuit). It takes the secret as input.
    component hasher = Poseidon(1);
    hasher.inputs[0] <== secret;

    // ─── Constraint ────────────────────────────────────────────
    // The core constraint: the hash of our secret MUST equal the
    // stored public hash. If this fails, the proof is invalid and
    // authentication is denied.
    publicHash === hasher.out;
}

// Export the circuit with publicHash as the only public input.
// The secret remains private (never included in the proof).
component main {public [publicHash]} = SecretProof();
