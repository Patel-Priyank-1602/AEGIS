import { useState, useEffect, useRef } from 'react'
import { Shield, Eye, EyeOff, Lock, User, Zap, ArrowRight, Fingerprint, CheckCircle, Cpu, Globe } from 'lucide-react'
import { useZKAuth } from '../hooks/useZKAuth'

interface Props {
  onLogin: (token: string, username: string) => void
}

// Floating particle component
function Particles() {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const resize = () => {
      canvas.width = window.innerWidth
      canvas.height = window.innerHeight
    }
    resize()
    window.addEventListener('resize', resize)

    const particles: { x: number; y: number; vx: number; vy: number; r: number; o: number }[] = []
    for (let i = 0; i < 60; i++) {
      particles.push({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        vx: (Math.random() - 0.5) * 0.3,
        vy: (Math.random() - 0.5) * 0.3,
        r: Math.random() * 2 + 0.5,
        o: Math.random() * 0.3 + 0.05,
      })
    }

    let frame: number
    const animate = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height)
      particles.forEach(p => {
        p.x += p.vx; p.y += p.vy
        if (p.x < 0) p.x = canvas.width
        if (p.x > canvas.width) p.x = 0
        if (p.y < 0) p.y = canvas.height
        if (p.y > canvas.height) p.y = 0

        ctx.beginPath()
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2)
        ctx.fillStyle = `rgba(129, 140, 248, ${p.o})`
        ctx.fill()
      })

      // Draw connections
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x
          const dy = particles[i].y - particles[j].y
          const dist = Math.sqrt(dx * dx + dy * dy)
          if (dist < 120) {
            ctx.beginPath()
            ctx.moveTo(particles[i].x, particles[i].y)
            ctx.lineTo(particles[j].x, particles[j].y)
            ctx.strokeStyle = `rgba(129, 140, 248, ${0.03 * (1 - dist / 120)})`
            ctx.lineWidth = 0.5
            ctx.stroke()
          }
        }
      }
      frame = requestAnimationFrame(animate)
    }
    animate()

    return () => {
      cancelAnimationFrame(frame)
      window.removeEventListener('resize', resize)
    }
  }, [])

  return <canvas ref={canvasRef} style={{ position: 'fixed', inset: 0, zIndex: 0, pointerEvents: 'none' }} />
}

export default function Login({ onLogin }: Props) {
  const [isRegister, setIsRegister] = useState(false)
  const [username, setUsername] = useState('')
  const [secret, setSecret] = useState('')
  const [showSecret, setShowSecret] = useState(false)
  const { login, register, loading, error } = useZKAuth()
  const [mounted, setMounted] = useState(false)

  useEffect(() => { setMounted(true) }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    const result = isRegister
      ? await register(username, secret)
      : await login(username, secret)

    if (result) {
      onLogin(result.token, result.username)
    }
  }

  const steps = [
    { icon: Lock, text: 'Secret hashed locally in browser', delay: '0.6s' },
    { icon: Cpu, text: 'ZK proof generated client-side', delay: '0.7s' },
    { icon: Globe, text: 'Only proof transmitted to server', delay: '0.8s' },
    { icon: CheckCircle, text: 'Identity verified without exposure', delay: '0.9s' },
  ]

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '40px',
      position: 'relative',
      overflow: 'hidden',
    }}>
      <Particles />

      {/* Gradient orbs */}
      <div style={{
        position: 'absolute', width: '600px', height: '600px',
        background: 'radial-gradient(circle, rgba(129,140,248,0.1) 0%, transparent 65%)',
        top: '-15%', right: '-15%', borderRadius: '50%',
        animation: 'ambientDrift 18s ease-in-out infinite',
      }} />
      <div style={{
        position: 'absolute', width: '500px', height: '500px',
        background: 'radial-gradient(circle, rgba(6,214,160,0.07) 0%, transparent 65%)',
        bottom: '-10%', left: '-10%', borderRadius: '50%',
        animation: 'ambientDrift 22s ease-in-out infinite reverse',
      }} />

      <div style={{
        width: '100%',
        maxWidth: '1000px',
        display: 'flex',
        alignItems: 'center',
        gap: '60px',
        position: 'relative',
        zIndex: 1,
      }}>
        
        {/* Left Side - Hero / How it works */}
        <div style={{
          flex: 1,
          opacity: mounted ? 1 : 0, transform: mounted ? 'translateX(0)' : 'translateX(-20px)',
          transition: 'all 0.8s cubic-bezier(0.4, 0, 0.2, 1)',
        }}>
          <div style={{ marginBottom: '40px' }}>
            <div style={{
              marginBottom: '24px',
              display: 'flex', alignItems: 'center', justifyContent: 'flex-start',
            }}>
              <img src="/favicon.png" alt="AEGIS" style={{ width: 112, height: 112, filter: 'drop-shadow(0 0 16px rgba(129,140,248,0.6))' }} />
            </div>
            <h1 style={{
              fontSize: '3rem', fontWeight: 900, letterSpacing: '0.15em', marginBottom: '16px',
              background: 'var(--gradient-primary)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
            }}>AEGIS</h1>
            <p style={{ color: 'var(--text-secondary)', fontSize: '1.05rem', fontWeight: 400, lineHeight: 1.6, maxWidth: '400px' }}>
              Zero-Trust AI Security Platform.<br/>
              Enterprise-grade threat intelligence and automated incident response.
            </p>
          </div>

          {/* How it works Box */}
          <div style={{
            padding: '28px',
            background: 'rgba(10, 15, 30, 0.6)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-xl)',
            backdropFilter: 'blur(12px)',
            maxWidth: '420px',
          }}>
            <div style={{
              fontWeight: 800, color: 'var(--text-primary)', marginBottom: '24px',
              fontSize: '0.95rem', display: 'flex', alignItems: 'center', gap: '10px',
              textTransform: 'uppercase', letterSpacing: '0.08em',
            }}>
              <Shield size={18} color="var(--accent-indigo)" />
              How ZK Authentication Works
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
              {steps.map((step, i) => (
                <div key={i} style={{
                  display: 'flex', alignItems: 'center', gap: '16px',
                  opacity: mounted ? 1 : 0,
                  transform: mounted ? 'translateX(0)' : 'translateX(-10px)',
                  transition: `all 0.5s cubic-bezier(0.4, 0, 0.2, 1) ${step.delay}`,
                }}>
                  <div style={{
                    width: 38, height: 38, borderRadius: 10,
                    background: 'rgba(129,140,248,0.08)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    flexShrink: 0,
                    border: '1px solid rgba(129,140,248,0.15)',
                  }}>
                    <step.icon size={18} color="var(--accent-indigo)" />
                  </div>
                  <div style={{
                    fontSize: '0.85rem', color: 'var(--text-muted)', lineHeight: 1.5,
                  }}>
                    <span style={{ color: 'var(--text-secondary)', fontWeight: 700, marginRight: '6px' }}>
                      Step {i + 1}:
                    </span>
                    {step.text}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right Side - Auth Box */}
        <div style={{
          flexShrink: 0,
          width: '440px',
          opacity: mounted ? 1 : 0, transform: mounted ? 'translateX(0)' : 'translateX(20px)',
          transition: 'all 0.8s cubic-bezier(0.4, 0, 0.2, 1)',
        }}>
          {/* Card */}
          <div style={{
            background: 'rgba(12, 17, 35, 0.7)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-xl)',
            padding: '36px',
            backdropFilter: 'blur(24px) saturate(1.3)',
            WebkitBackdropFilter: 'blur(24px) saturate(1.3)',
            boxShadow: '0 16px 64px rgba(0,0,0,0.4), 0 0 1px rgba(129,140,248,0.1)',
          }}>
            {/* ZK Indicator */}
            <div style={{
              display: 'flex', alignItems: 'center', gap: '10px',
              padding: '12px 16px', borderRadius: 'var(--radius-sm)',
              background: 'rgba(6,214,160,0.05)',
              border: '1px solid rgba(6,214,160,0.12)',
              marginBottom: '28px',
            }}>
              <div style={{
                width: 32, height: 32, borderRadius: 8,
                background: 'rgba(6,214,160,0.1)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <Fingerprint size={16} color="var(--accent-cyan)" />
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--accent-cyan)' }}>
                  ZK-SNARK Authentication
                </div>
                <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>
                  No password transmitted over network
                </div>
              </div>
            </div>

            <h2 style={{ fontSize: '1.25rem', fontWeight: 800, marginBottom: '24px', letterSpacing: '-0.01em' }}>
              {isRegister ? 'Create Identity' : 'Authenticate'}
            </h2>

            <form onSubmit={handleSubmit}>
              {/* Username */}
              <div style={{ marginBottom: '18px' }}>
                <label style={{
                  display: 'block', fontSize: '0.72rem', fontWeight: 700,
                  color: 'var(--text-secondary)', textTransform: 'uppercase',
                  letterSpacing: '0.1em', marginBottom: '8px',
                }}>Username</label>
                <div style={{ position: 'relative' }}>
                  <User size={16} style={{
                    position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)',
                    color: 'var(--text-muted)',
                  }} />
                  <input
                    id="login-username"
                    className="input"
                    style={{ paddingLeft: '42px' }}
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
                <label style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  fontSize: '0.72rem', fontWeight: 700,
                  color: 'var(--text-secondary)', textTransform: 'uppercase',
                  letterSpacing: '0.1em', marginBottom: '8px',
                }}>
                  Secret Phrase
                  <span style={{
                    color: 'var(--text-muted)', fontWeight: 500,
                    textTransform: 'none', letterSpacing: 'normal', fontSize: '0.65rem',
                  }}>
                    stays in your browser
                  </span>
                </label>
                <div style={{ position: 'relative' }}>
                  <Lock size={16} style={{
                    position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)',
                    color: 'var(--text-muted)',
                  }} />
                  <input
                    id="login-secret"
                    className="input"
                    style={{ paddingLeft: '42px', paddingRight: '46px', fontFamily: 'var(--font-mono)' }}
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
                      position: 'absolute', right: '12px', top: '50%', transform: 'translateY(-50%)',
                      background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)',
                      padding: '4px', borderRadius: '4px', transition: 'color 0.2s',
                    }}
                  >
                    {showSecret ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>

              {/* Error */}
              {error && (
                <div style={{
                  padding: '12px 16px', borderRadius: 'var(--radius-sm)',
                  background: 'var(--danger-bg)', border: '1px solid var(--danger-border)',
                  color: 'var(--danger)', fontSize: '0.8rem', marginBottom: '18px',
                  display: 'flex', alignItems: 'center', gap: '8px',
                }}>
                  <Shield size={14} />
                  {error}
                </div>
              )}

              {/* Submit */}
              <button
                id="login-submit"
                className="btn btn-primary"
                type="submit"
                disabled={loading || !username || !secret}
                style={{
                  width: '100%', justifyContent: 'center', padding: '15px', fontSize: '0.9rem',
                  opacity: loading ? 0.7 : 1, fontWeight: 700, letterSpacing: '0.02em',
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
            <div style={{ textAlign: 'center', marginTop: '22px', fontSize: '0.84rem', color: 'var(--text-secondary)' }}>
              {isRegister ? 'Already registered?' : "Don't have an account?"}{' '}
              <button
                onClick={() => setIsRegister(!isRegister)}
                style={{
                  background: 'none', border: 'none', color: 'var(--accent-indigo)',
                  cursor: 'pointer', fontWeight: 700, fontSize: '0.84rem',
                  transition: 'color 0.2s',
                }}
              >
                {isRegister ? 'Sign In' : 'Register'}
              </button>
            </div>
          </div>
        </div>

      </div>
    </div>
  )
}
