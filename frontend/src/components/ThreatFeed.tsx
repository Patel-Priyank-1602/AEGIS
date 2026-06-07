import { ThreatEvent } from '../hooks/useWebSocket'
import { Terminal, Globe, FileText, Cpu, Shield, AlertTriangle, Hexagon, Brain, Activity } from 'lucide-react'

interface Props {
  events: ThreatEvent[]
}

export default function ThreatFeed({ events }: Props) {
  const getIcon = (type: string) => {
    switch (type) {
      case 'network_connect': return <Globe size={13} />
      case 'process_exec': return <Cpu size={13} />
      default: return <FileText size={13} />
    }
  }

  return (
    <div className="card" style={{ padding: '22px', height: '480px', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '18px' }}>
        <h2 style={{
          fontSize: '0.72rem', fontWeight: 700, textTransform: 'uppercase',
          letterSpacing: '0.1em', color: 'var(--text-muted)',
          display: 'flex', alignItems: 'center', gap: '8px',
        }}>
          <div style={{
            width: 24, height: 24, borderRadius: 6,
            background: 'rgba(129,140,248,0.08)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <Terminal size={12} color="var(--accent-indigo)" />
          </div>
          Live Event Feed
        </h2>
        <div style={{
          display: 'flex', alignItems: 'center', gap: '6px',
          fontSize: '0.68rem', color: 'var(--text-muted)',
          fontFamily: 'var(--font-mono)',
          padding: '4px 10px', borderRadius: '100px',
          background: 'rgba(129,140,248,0.05)',
          border: '1px solid var(--border)',
        }}>
          <Activity size={10} />
          {events.length} events
        </div>
      </div>

      <div style={{
        flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '6px',
      }}>
        {events.length === 0 ? (
          <div style={{
            flex: 1, display: 'flex', flexDirection: 'column',
            alignItems: 'center', justifyContent: 'center', gap: '12px',
            color: 'var(--text-muted)',
          }}>
            <div style={{
              width: 48, height: 48, borderRadius: 14,
              background: 'rgba(129,140,248,0.06)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              animation: 'float 3s ease-in-out infinite',
            }}>
              <Activity size={22} color="var(--text-muted)" />
            </div>
            <div style={{ fontSize: '0.85rem', fontWeight: 500 }}>Waiting for events...</div>
            <div style={{ fontSize: '0.72rem' }}>Connect an agent or enable demo mode</div>
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
                background: event.threat_level === 'danger' ? 'rgba(248,113,113,0.05)'
                  : event.threat_level === 'warning' ? 'rgba(251,191,36,0.04)'
                  : 'rgba(255,255,255,0.01)',
                borderColor: event.threat_level === 'danger' ? 'var(--danger-border)'
                  : event.threat_level === 'warning' ? 'var(--warning-border)'
                  : 'var(--border)',
                animationDelay: `${i * 25}ms`,
                transition: 'all 0.25s var(--ease-smooth)',
              }}
            >
              {/* Main row */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                {/* Score badge */}
                <div style={{
                  minWidth: '38px', textAlign: 'center',
                  fontFamily: 'var(--font-mono)', fontSize: '0.75rem', fontWeight: 800,
                  padding: '4px 6px', borderRadius: '8px',
                  background: event.threat_level === 'danger' ? 'rgba(248,113,113,0.12)'
                    : event.threat_level === 'warning' ? 'rgba(251,191,36,0.12)'
                    : 'rgba(6,214,160,0.08)',
                  color: event.threat_level === 'danger' ? 'var(--danger)'
                    : event.threat_level === 'warning' ? 'var(--warning)'
                    : 'var(--safe)',
                  boxShadow: event.threat_level === 'danger' ? '0 0 8px rgba(248,113,113,0.1)' : 'none',
                }}>
                  {event.threat_score.toFixed(0)}
                </div>

                {/* Icon */}
                <div style={{
                  width: 24, height: 24, borderRadius: 6,
                  background: 'rgba(255,255,255,0.03)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  color: 'var(--text-muted)',
                }}>
                  {getIcon(event.type)}
                </div>

                {/* Details */}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{
                    fontSize: '0.8rem', fontWeight: 700,
                    fontFamily: 'var(--font-mono)',
                    color: event.threat_level === 'danger' ? 'var(--danger)' : 'var(--text-primary)',
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                  }}>
                    {event.process}
                    <span style={{ color: 'var(--text-muted)', fontWeight: 400, marginLeft: '6px', fontSize: '0.68rem' }}>
                      PID {event.pid}
                    </span>
                  </div>
                  <div style={{
                    fontSize: '0.68rem', color: 'var(--text-muted)',
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
                      fontSize: '0.55rem', padding: '2px 7px', borderRadius: '5px',
                      background: 'rgba(248,113,113,0.15)', color: 'var(--danger)',
                      fontWeight: 800, letterSpacing: '0.05em',
                      border: '1px solid rgba(248,113,113,0.2)',
                    }}>IOC</span>
                  )}
                  {event.honeypot_hit && (
                    <span title="Honeypot Hit" style={{
                      fontSize: '0.55rem', padding: '2px 7px', borderRadius: '5px',
                      background: 'rgba(244,114,182,0.15)', color: '#f472b6',
                      fontWeight: 800,
                      border: '1px solid rgba(244,114,182,0.2)',
                    }}>TRAP</span>
                  )}
                  {event.lateral_movement_detected && (
                    <span title="Lateral Movement" style={{
                      fontSize: '0.55rem', padding: '2px 7px', borderRadius: '5px',
                      background: 'rgba(251,146,60,0.15)', color: '#fb923c',
                      fontWeight: 800,
                      border: '1px solid rgba(251,146,60,0.2)',
                    }}>LATERAL</span>
                  )}
                </div>

                {/* Timestamp */}
                <div style={{
                  fontSize: '0.62rem', color: 'var(--text-muted)',
                  fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap',
                  padding: '2px 8px', borderRadius: '4px',
                  background: 'rgba(255,255,255,0.02)',
                }}>
                  {new Date(event.timestamp).toLocaleTimeString()}
                </div>
              </div>

              {/* MITRE ATT&CK tags row */}
              {event.mitre_techniques && event.mitre_techniques.length > 0 && (
                <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap', paddingLeft: '48px' }}>
                  {event.mitre_techniques.slice(0, 3).map((t, j) => (
                    <span key={j} title={`${t.tactic}: ${t.description}`} style={{
                      fontSize: '0.58rem', padding: '2px 7px', borderRadius: '4px',
                      background: 'rgba(251,191,36,0.08)', color: 'var(--warning)',
                      fontFamily: 'var(--font-mono)', fontWeight: 700,
                      border: '1px solid rgba(251,191,36,0.15)',
                    }}>
                      {t.id}
                    </span>
                  ))}
                  {event.mitre_techniques.length > 3 && (
                    <span style={{ fontSize: '0.58rem', color: 'var(--text-muted)' }}>
                      +{event.mitre_techniques.length - 3}
                    </span>
                  )}
                </div>
              )}

              {/* LLM Explanation */}
              {event.explanation && (
                <div style={{
                  paddingLeft: '48px', fontSize: '0.7rem', color: 'var(--text-muted)',
                  lineHeight: 1.5, borderTop: '1px solid var(--border)',
                  paddingTop: '6px', marginTop: '2px',
                }}>
                  <Brain size={10} style={{ marginRight: '6px', verticalAlign: 'middle', color: 'var(--accent)' }} />
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
