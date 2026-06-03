import { ThreatEvent } from '../hooks/useWebSocket'
import { Terminal, Globe, FileText, Cpu, Shield, AlertTriangle, Hexagon, Brain } from 'lucide-react'

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
                display: 'flex', flexDirection: 'column', gap: '6px',
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
              {/* Main row */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
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

                {/* Enrichment badges */}
                <div style={{ display: 'flex', gap: '4px', flexShrink: 0 }}>
                  {event.ioc_matched && (
                    <span title="IOC Match" style={{
                      fontSize: '0.55rem', padding: '2px 6px', borderRadius: '4px',
                      background: 'rgba(239,68,68,0.2)', color: 'var(--danger)',
                      fontWeight: 700, letterSpacing: '0.05em',
                    }}>IOC</span>
                  )}
                  {event.honeypot_hit && (
                    <span title="Honeypot Hit" style={{
                      fontSize: '0.55rem', padding: '2px 6px', borderRadius: '4px',
                      background: 'rgba(236,72,153,0.2)', color: '#ec4899',
                      fontWeight: 700,
                    }}>🍯 TRAP</span>
                  )}
                  {event.lateral_movement_detected && (
                    <span title="Lateral Movement" style={{
                      fontSize: '0.55rem', padding: '2px 6px', borderRadius: '4px',
                      background: 'rgba(249,115,22,0.2)', color: '#f97316',
                      fontWeight: 700,
                    }}>LATERAL</span>
                  )}
                </div>

                {/* Timestamp */}
                <div style={{
                  fontSize: '0.65rem', color: 'var(--text-muted)',
                  fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap',
                }}>
                  {new Date(event.timestamp).toLocaleTimeString()}
                </div>
              </div>

              {/* MITRE ATT&CK tags row */}
              {event.mitre_techniques && event.mitre_techniques.length > 0 && (
                <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap', paddingLeft: '46px' }}>
                  {event.mitre_techniques.slice(0, 3).map((t, j) => (
                    <span key={j} title={`${t.tactic}: ${t.description}`} style={{
                      fontSize: '0.6rem', padding: '1px 6px', borderRadius: '3px',
                      background: 'rgba(251,191,36,0.12)', color: 'var(--warning)',
                      fontFamily: 'var(--font-mono)', fontWeight: 600,
                      border: '1px solid rgba(251,191,36,0.2)',
                    }}>
                      {t.id}
                    </span>
                  ))}
                  {event.mitre_techniques.length > 3 && (
                    <span style={{ fontSize: '0.6rem', color: 'var(--text-muted)' }}>
                      +{event.mitre_techniques.length - 3}
                    </span>
                  )}
                </div>
              )}

              {/* LLM Explanation */}
              {event.explanation && (
                <div style={{
                  paddingLeft: '46px', fontSize: '0.7rem', color: 'var(--text-muted)',
                  lineHeight: 1.5, borderTop: '1px solid var(--border)',
                  paddingTop: '6px', marginTop: '2px',
                }}>
                  <Brain size={10} style={{ marginRight: '4px', verticalAlign: 'middle', color: 'var(--accent)' }} />
                  {event.explanation.substring(0, 200)}{event.explanation.length > 200 ? '...' : ''}
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  )
}
