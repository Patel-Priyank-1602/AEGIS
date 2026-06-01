import { ThreatEvent } from '../hooks/useWebSocket'
import { Terminal, Globe, FileText, Cpu } from 'lucide-react'

interface Props {
  events: ThreatEvent[]
}

export default function ThreatFeed({ events }: Props) {
  const getIcon = (type: string) => {
    switch (type) {
      case 'network_connect': return <Globe size={14} />
      case 'process_exec': return <Cpu size={14} />
      default: return <FileText size={14} />
    }
  }

  return (
    <div className="card" style={{ padding: '20px', height: '480px', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
        <h2 style={{
          fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase',
          letterSpacing: '0.08em', color: 'var(--text-muted)',
          display: 'flex', alignItems: 'center', gap: '8px',
        }}>
          <Terminal size={14} />
          Live Event Feed
        </h2>
        <span style={{
          fontSize: '0.7rem', color: 'var(--text-muted)',
          fontFamily: 'var(--font-mono)',
        }}>
          {events.length} events
        </span>
      </div>

      <div style={{
        flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '6px',
      }}>
        {events.length === 0 ? (
          <div style={{
            flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: 'var(--text-muted)', fontSize: '0.85rem',
          }}>
            Waiting for events...
          </div>
        ) : (
          events.slice(0, 50).map((event, i) => (
            <div
              key={`${event.pid}-${event.timestamp}-${i}`}
              className="slide-in"
              style={{
                display: 'flex', alignItems: 'center', gap: '10px',
                padding: '10px 12px', borderRadius: 'var(--radius-sm)',
                border: '1px solid',
                background: event.threat_level === 'danger' ? 'var(--danger-bg)'
                  : event.threat_level === 'warning' ? 'var(--warning-bg)'
                  : 'rgba(255,255,255,0.01)',
                borderColor: event.threat_level === 'danger' ? 'var(--danger-border)'
                  : event.threat_level === 'warning' ? 'var(--warning-border)'
                  : 'var(--border)',
                animationDelay: `${i * 30}ms`,
                transition: 'all 0.2s',
              }}
            >
              {/* Score badge */}
              <div style={{
                minWidth: '36px', textAlign: 'center',
                fontFamily: 'var(--font-mono)', fontSize: '0.75rem', fontWeight: 700,
                padding: '3px 6px', borderRadius: '6px',
                background: event.threat_level === 'danger' ? 'rgba(239,68,68,0.15)'
                  : event.threat_level === 'warning' ? 'rgba(251,191,36,0.15)'
                  : 'rgba(6,214,160,0.1)',
                color: event.threat_level === 'danger' ? 'var(--danger)'
                  : event.threat_level === 'warning' ? 'var(--warning)'
                  : 'var(--safe)',
              }}>
                {event.threat_score.toFixed(0)}
              </div>

              {/* Icon */}
              <div style={{ color: 'var(--text-muted)' }}>
                {getIcon(event.type)}
              </div>

              {/* Details */}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{
                  fontSize: '0.8rem', fontWeight: 600,
                  fontFamily: 'var(--font-mono)',
                  color: event.threat_level === 'danger' ? 'var(--danger)' : 'var(--text-primary)',
                  overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                }}>
                  {event.process}
                  <span style={{ color: 'var(--text-muted)', fontWeight: 400, marginLeft: '6px', fontSize: '0.7rem' }}>
                    PID {event.pid}
                  </span>
                </div>
                <div style={{
                  fontSize: '0.7rem', color: 'var(--text-muted)',
                  overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                }}>
                  {event.file || event.ip}
                  {event.port > 0 && `:${event.port}`}
                </div>
              </div>

              {/* Timestamp */}
              <div style={{
                fontSize: '0.65rem', color: 'var(--text-muted)',
                fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap',
              }}>
                {new Date(event.timestamp).toLocaleTimeString()}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
