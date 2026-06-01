import { useState } from 'react'
import { Shield, Eye, EyeOff, Lock, User, Zap, ArrowRight, Fingerprint } from 'lucide-react'
import { useZKAuth } from '../hooks/useZKAuth'

interface Props {
  onLogin: (token: string, username: string) => void
}

export default function Login({ onLogin }: Props) {
  const [isRegister, setIsRegister] = useState(false)
  const [username, setUsername] = useState('')
  const [secret, setSecret] = useState('')
  const [showSecret, setShowSecret] = useState(false)
  const { login, register, loading, error } = useZKAuth()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    const result = isRegister
      ? await register(username, secret)
      : await login(username, secret)

    if (result) {
      onLogin(result.token, result.username)
    }
  }

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '20px',
      position: 'relative',
      overflow: 'hidden',
    }}>
      {/* Animated background orbs */}
      <div style={{
        position: 'absolute', width: '500px', height: '500px',
        background: 'radial-gradient(circle, rgba(99,102,241,0.12) 0%, transparent 70%)',
        top: '-10%', right: '-10%', borderRadius: '50%',
        animation: 'ambientDrift 15s ease-in-out infinite',
      }} />
      <div style={{
        position: 'absolute', width: '400px', height: '400px',
        background: 'radial-gradient(circle, rgba(6,214,160,0.08) 0%, transparent 70%)',
        bottom: '-5%', left: '-5%', borderRadius: '50%',
        animation: 'ambientDrift 20s ease-in-out infinite reverse',
      }} />

      <div className="fade-in" style={{ width: '100%', maxWidth: '440px', position: 'relative', zIndex: 1 }}>
        {/* Logo */}
        <div style={{ textAlign: 'center', marginBottom: '40px' }}>
          <div style={{
            width: '72px', height: '72px', margin: '0 auto 20px',
            background: 'var(--gradient-primary)',
            borderRadius: '20px',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            boxShadow: '0 8px 32px rgba(99,102,241,0.25)',
          }}>
            <Shield size={36} color="white" />
          </div>
          <h1 style={{ fontSize: '2rem', fontWeight: 800, letterSpacing: '0.15em', marginBottom: '8px',
            background: 'var(--gradient-primary)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
          }}>AEGIS</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
            Zero-Trust AI Security Platform
          </p>
        </div>

        {/* Card */}
        <div style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-xl)',
          padding: '36px',
          backdropFilter: 'blur(20px)',
        }}>
          {/* ZK Indicator */}
          <div style={{
            display: 'flex', alignItems: 'center', gap: '8px',
            padding: '10px 16px', borderRadius: 'var(--radius-sm)',
            background: 'rgba(6,214,160,0.06)', border: '1px solid rgba(6,214,160,0.15)',
            marginBottom: '28px', fontSize: '0.8rem', color: 'var(--accent-cyan)',
          }}>
            <Fingerprint size={16} />
            <span style={{ fontWeight: 600 }}>ZK-SNARK Authentication</span>
            <span style={{ color: 'var(--text-muted)', marginLeft: 'auto', fontSize: '0.7rem' }}>No password transmitted</span>
          </div>

          <h2 style={{ fontSize: '1.2rem', fontWeight: 700, marginBottom: '24px' }}>
            {isRegister ? 'Create Identity' : 'Authenticate'}
          </h2>

          <form onSubmit={handleSubmit}>
            {/* Username */}
            <div style={{ marginBottom: '16px' }}>
              <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600,
                color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.08em',
                marginBottom: '8px',
              }}>Username</label>
              <div style={{ position: 'relative' }}>
                <User size={16} style={{ position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                <input
                  id="login-username"
                  className="input"
                  style={{ paddingLeft: '40px' }}
                  type="text"
                  value={username}
                  onChange={e => setUsername(e.target.value)}
                  placeholder="Enter your username"
                  required
                  minLength={3}
                  autoComplete="username"
                />
              </div>
            </div>

            {/* Secret */}
            <div style={{ marginBottom: '24px' }}>
              <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600,
                color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.08em',
                marginBottom: '8px',
              }}>
                Secret Phrase
                <span style={{ color: 'var(--text-muted)', fontWeight: 400, textTransform: 'none', letterSpacing: 'normal', marginLeft: '8px' }}>
                  (stays in your browser)
                </span>
              </label>
              <div style={{ position: 'relative' }}>
                <Lock size={16} style={{ position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                <input
                  id="login-secret"
                  className="input"
                  style={{ paddingLeft: '40px', paddingRight: '44px', fontFamily: 'var(--font-mono)' }}
                  type={showSecret ? 'text' : 'password'}
                  value={secret}
                  onChange={e => setSecret(e.target.value)}
                  placeholder="Enter your secret phrase"
                  required
                  minLength={4}
                  autoComplete="current-password"
                />
                <button
                  type="button"
                  onClick={() => setShowSecret(!showSecret)}
                  style={{
                    position: 'absolute', right: '10px', top: '50%', transform: 'translateY(-50%)',
                    background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)',
                    padding: '4px',
                  }}
                >
                  {showSecret ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            {/* Error */}
            {error && (
              <div style={{
                padding: '10px 14px', borderRadius: 'var(--radius-sm)',
                background: 'var(--danger-bg)', border: '1px solid var(--danger-border)',
                color: 'var(--danger)', fontSize: '0.8rem', marginBottom: '16px',
              }}>
                {error}
              </div>
            )}

            {/* Submit */}
            <button
              id="login-submit"
              className="btn btn-primary"
              type="submit"
              disabled={loading || !username || !secret}
              style={{ width: '100%', justifyContent: 'center', padding: '14px', fontSize: '0.9rem',
                opacity: loading ? 0.7 : 1,
              }}
            >
              {loading ? (
                <>
                  <Zap size={16} style={{ animation: 'pulse 1s infinite' }} />
                  Generating ZK Proof...
                </>
              ) : (
                <>
                  {isRegister ? 'Create ZK Identity' : 'Prove Identity'}
                  <ArrowRight size={16} />
                </>
              )}
            </button>
          </form>

          {/* Toggle */}
          <div style={{ textAlign: 'center', marginTop: '20px', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            {isRegister ? 'Already registered?' : "Don't have an account?"}{' '}
            <button
              onClick={() => { setIsRegister(!isRegister); setError && undefined }}
              style={{
                background: 'none', border: 'none', color: 'var(--accent-indigo)',
                cursor: 'pointer', fontWeight: 600, fontSize: '0.85rem',
              }}
            >
              {isRegister ? 'Sign In' : 'Register'}
            </button>
          </div>
        </div>

        {/* How it works */}
        <div style={{
          marginTop: '24px', padding: '16px 20px',
          background: 'rgba(13,18,37,0.5)', border: '1px solid var(--border)',
          borderRadius: 'var(--radius-md)', fontSize: '0.75rem', color: 'var(--text-muted)',
          lineHeight: 1.7,
        }}>
          <div style={{ fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '4px' }}>
            🔐 How ZK Authentication Works
          </div>
          <div>1. Your secret phrase is hashed <strong>locally in your browser</strong></div>
          <div>2. A mathematical proof is generated (secret never sent)</div>
          <div>3. Only the proof is transmitted to verify your identity</div>
          <div>4. Even if intercepted, the proof cannot reveal your secret</div>
        </div>
      </div>
    </div>
  )
}
