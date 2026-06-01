import { useState } from 'react'
import { AlertTriangle, X, Skull } from 'lucide-react'
import { ThreatEvent } from '../hooks/useWebSocket'

interface Props {
  event: ThreatEvent
}

export default function AlertBanner({ event }: Props) {
  const [dismissed, setDismissed] = useState(false)

  if (dismissed) return null

  return (
    <div className="slide-in" style={{
      display: 'flex', alignItems: 'center', gap: '14px',
      padding: '14px 20px', borderRadius: 'var(--radius-md)',
      background: 'linear-gradient(135deg, rgba(239,68,68,0.12) 0%, rgba(249,115,22,0.08) 100%)',
      border: '1px solid var(--danger-border)',
      marginBottom: '20px',
      animation: 'slideIn 0.3s ease-out, dangerPulse 2s ease-in-out infinite',
    }}>
      <div style={{
        width: '40px', height: '40px', borderRadius: '10px',
        background: 'rgba(239,68,68,0.15)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        flexShrink: 0,
      }}>
        <Skull size={20} color="var(--danger)" />
      </div>

      <div style={{ flex: 1 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '2px' }}>
          <AlertTriangle size={14} color="var(--danger)" />
          <span style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--danger)' }}>
            Threat Detected — Score {event.threat_score.toFixed(0)}/100
          </span>
        </div>
        <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
          <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{event.process}</span> (PID {event.pid})
          {event.file && <> accessed <span style={{ fontFamily: 'var(--font-mono)' }}>{event.file}</span></>}
          {event.ip !== '127.0.0.1' && <> → <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--danger)' }}>{event.ip}:{event.port}</span></>}
        </div>
      </div>

      <button
        onClick={() => setDismissed(true)}
        style={{
          background: 'none', border: 'none', cursor: 'pointer',
          color: 'var(--text-muted)', padding: '4px',
        }}
      >
        <X size={18} />
      </button>
    </div>
  )
}
