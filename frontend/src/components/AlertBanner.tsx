import { useState } from 'react'
import { AlertTriangle, X, Skull, Shield } from 'lucide-react'
import { ThreatEvent } from '../hooks/useWebSocket'

interface Props {
  event: ThreatEvent
}

export default function AlertBanner({ event }: Props) {
  const [dismissed, setDismissed] = useState(false)

  if (dismissed) return null

  return (
    <div className="slide-in" style={{
      display: 'flex', alignItems: 'center', gap: '16px',
      padding: '16px 22px', borderRadius: 'var(--radius-lg)',
      background: 'linear-gradient(135deg, rgba(248,113,113,0.1) 0%, rgba(251,146,60,0.06) 100%)',
      border: '1px solid var(--danger-border)',
      marginBottom: '22px',
      animation: 'slideIn 0.4s ease-out, dangerPulse 2s ease-in-out infinite',
      backdropFilter: 'blur(12px)',
      position: 'relative',
      overflow: 'hidden',
    }}>
      {/* Animated border gradient */}
      <div style={{
        position: 'absolute', top: 0, left: 0, right: 0, height: '2px',
        background: 'linear-gradient(90deg, transparent, var(--danger), transparent)',
        opacity: 0.6,
      }} />

      <div style={{
        width: 44, height: 44, borderRadius: 12,
        background: 'rgba(248,113,113,0.12)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        flexShrink: 0,
        boxShadow: '0 0 20px rgba(248,113,113,0.1)',
      }}>
        <Skull size={22} color="var(--danger)" />
      </div>

      <div style={{ flex: 1 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
          <AlertTriangle size={14} color="var(--danger)" />
          <span style={{ fontSize: '0.88rem', fontWeight: 800, color: 'var(--danger)' }}>
            Threat Detected — Score {event.threat_score.toFixed(0)}/100
          </span>
          <span style={{
            fontSize: '0.6rem', fontWeight: 700, padding: '2px 8px', borderRadius: '100px',
            background: 'rgba(248,113,113,0.15)', color: 'var(--danger)',
            fontFamily: 'var(--font-mono)', letterSpacing: '0.05em',
          }}>CRITICAL</span>
        </div>
        <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
          <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}>{event.process}</span> (PID {event.pid})
          {event.file && <> accessed <span style={{ fontFamily: 'var(--font-mono)' }}>{event.file}</span></>}
          {event.ip !== '127.0.0.1' && <> → <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--danger)' }}>{event.ip}:{event.port}</span></>}
        </div>
      </div>

      <button
        onClick={() => setDismissed(true)}
        style={{
          background: 'rgba(248,113,113,0.08)', border: '1px solid var(--danger-border)',
          cursor: 'pointer', color: 'var(--text-muted)',
          padding: '8px', borderRadius: '8px', transition: 'all 0.2s',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}
      >
        <X size={16} />
      </button>
    </div>
  )
}
