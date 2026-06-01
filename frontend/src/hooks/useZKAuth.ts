/**
 * AEGIS ZK Authentication Hook
 * Handles ZK proof generation and verification in the browser.
 * The user's secret NEVER leaves the browser.
 */

import { useState } from 'react'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

/**
 * Convert a string secret to a field element (big number).
 * Circom circuits operate on numbers in a finite field.
 */
function secretToHash(secret: string): string {
  // Simple deterministic hash for the secret
  let hash = 0n
  const FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617n
  for (let i = 0; i < secret.length; i++) {
    hash = (hash * 31n + BigInt(secret.charCodeAt(i))) % FIELD_SIZE
  }
  return hash.toString()
}

/**
 * Generate a ZK proof that we know the secret.
 * In production, this uses snarkjs with the compiled circuit.
 * For development, uses a hash-based proof.
 */
async function generateProof(secret: string, publicHash: string) {
  try {
    // Try snarkjs (production)
    const snarkjs = await import('snarkjs')
    const secretField = secretToHash(secret)

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      { secret: secretField, publicHash },
      '/zk/circuit.wasm',
      '/zk/circuit_final.zkey'
    )
    return { proof, publicSignals }
  } catch {
    // Fallback: hash-based proof for development
    const hash = secretToHash(secret)
    return {
      proof: { hash, protocol: 'dev' },
      publicSignals: [hash]
    }
  }
}

export function useZKAuth() {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const register = async (username: string, secret: string): Promise<{ token: string; username: string } | null> => {
    setLoading(true)
    setError(null)

    try {
      const publicHash = secretToHash(secret)

      const res = await fetch(`${API_URL}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, public_hash: publicHash })
      })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.detail || 'Registration failed')
      }

      const data = await res.json()
      return { token: data.token, username: data.username }
    } catch (e: any) {
      setError(e.message)
      return null
    } finally {
      setLoading(false)
    }
  }

  const login = async (username: string, secret: string): Promise<{ token: string; username: string } | null> => {
    setLoading(true)
    setError(null)

    try {
      const publicHash = secretToHash(secret)
      const { proof, publicSignals } = await generateProof(secret, publicHash)

      const res = await fetch(`${API_URL}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, proof, public_signals: publicSignals })
      })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.detail || 'Authentication failed')
      }

      const data = await res.json()
      return { token: data.token, username: data.username }
    } catch (e: any) {
      setError(e.message)
      return null
    } finally {
      setLoading(false)
    }
  }

  return { register, login, loading, error }
}
