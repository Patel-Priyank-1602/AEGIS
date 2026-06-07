import { useState, useEffect } from 'react'
import { Zap, Play, RotateCcw, AlertTriangle, Shield, Clock, ChevronRight, Settings } from 'lucide-react'
import { api } from '../services/api'

export default function Playbooks() {
  const [playbooks, setPlaybooks] = useState<any>(null)
  const [executions, setExecutions] = useState<any[]>([])
  const [stats, setStats] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadData()
    const interval = setInterval(loadData, 10000)
    return () => clearInterval(interval)
  }, [])

  const loadData = async () => {
    try {
      const [pb, exec] = await Promise.all([
        api.getPlaybooks(),
        api.getPlaybookExecutions(20),
      ])
      setPlaybooks(pb.playbooks)
      setStats(pb.stats)
      setExecutions(exec.executions || [])
    } catch (e) { console.error(e) }
    finally { setLoading(false) }
  }

  const handleUndo = async (actionId: string) => {
    try {
      await api.undoAction(actionId)
      loadData()
    } catch (e) { console.error(e) }
  }

  const handleToggle = async () => {
    try {
      await api.togglePlaybooks(!stats?.enabled)
      loadData()
    } catch (e) { console.error(e) }
  }

  const severityColor = (s: string) =>
    s === 'critical' ? 'var(--danger)' : s === 'high' ? 'var(--warning)' : 'var(--safe)'
  const severityBg = (s: string) =>
    s === 'critical' ? 'rgba(248,113,113,0.08)' : s === 'high' ? 'rgba(251,191,36,0.08)' : 'rgba(6,214,160,0.08)'

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{
              width: 36, height: 36, borderRadius: 10,
              background: 'rgba(167,139,250,0.1)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <Zap size={20} color="#a78bfa" />
            </div>
            Automated Playbooks
          </h1>
          <p className="page-subtitle">Automated response actions with full undo capability</p>
        </div>
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          <div style={{
            padding: '6px 16px', borderRadius: '100px', fontSize: '0.72rem', fontWeight: 700,
            background: stats?.enabled ? 'var(--safe-bg)' : 'var(--danger-bg)',
            color: stats?.enabled ? 'var(--safe)' : 'var(--danger)',
            border: `1px solid ${stats?.enabled ? 'var(--safe-border)' : 'var(--danger-border)'}`,
            display: 'flex', alignItems: 'center', gap: '6px',
          }}>
            <div style={{
              width: 6, height: 6, borderRadius: '50%',
              background: stats?.enabled ? 'var(--safe)' : 'var(--danger)',
              boxShadow: stats?.enabled ? '0 0 6px rgba(6,214,160,0.4)' : '0 0 6px rgba(248,113,113,0.4)',
            }} />
            {stats?.enabled ? 'Active' : 'Disabled'}
          </div>
          <button className="btn btn-ghost" onClick={handleToggle}>
            <Settings size={14} />
            {stats?.enabled ? 'Disable' : 'Enable'}
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid-4" style={{ marginBottom: '24px' }}>
        {[
          { label: 'Executions', icon: Play, value: stats?.total_executions || 0, color: 'var(--accent)', bg: 'rgba(6,214,160,0.06)' },
          { label: 'Actions Taken', icon: Zap, value: stats?.total_actions || 0, color: 'var(--warning)', bg: 'rgba(251,191,36,0.06)' },
          { label: 'IPs Blocked', icon: Shield, value: stats?.blocked_ips || 0, color: 'var(--danger)', bg: 'rgba(248,113,113,0.06)' },
          { label: 'JWTs Revoked', icon: AlertTriangle, value: stats?.denied_jwts || 0, color: 'var(--text-primary)', bg: 'rgba(129,140,248,0.06)' },
        ].map((card, i) => (
          <div key={card.label} className="stat-card slide-in" style={{ animationDelay: `${i * 60}ms` }}>
            <div className="stat-label">
              <div style={{
                width: 22, height: 22, borderRadius: 6,
                background: card.bg,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <card.icon size={12} style={{ color: card.color }} />
              </div>
              {card.label}
            </div>
            <div className="stat-value" style={{ color: card.color }}>{card.value}</div>
          </div>
        ))}
      </div>

      <div className="grid-2-1">
        {/* Playbook Definitions */}
        <div className="card" style={{ padding: '22px' }}>
          <h2 style={{
            fontSize: '0.72rem', fontWeight: 700, textTransform: 'uppercase',
            letterSpacing: '0.1em', color: 'var(--text-muted)', marginBottom: '18px',
            display: 'flex', alignItems: 'center', gap: '8px',
          }}>
            <div style={{
              width: 24, height: 24, borderRadius: 6,
              background: 'rgba(167,139,250,0.08)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <Zap size={12} color="#a78bfa" />
            </div>
            Configured Playbooks
          </h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {playbooks && Object.entries(playbooks).map(([id, pb]: [string, any]) => (
              <div key={id} style={{
                padding: '16px 18px', borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--border)', background: 'rgba(255,255,255,0.015)',
                transition: 'all 0.2s',
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <span style={{ fontWeight: 700, fontSize: '0.88rem' }}>{pb.name}</span>
                  <span style={{
                    fontSize: '0.6rem', fontWeight: 800, padding: '3px 12px', borderRadius: '100px',
                    background: severityBg(pb.severity), color: severityColor(pb.severity),
                    border: `1px solid ${pb.severity === 'critical' ? 'var(--danger-border)' : pb.severity === 'high' ? 'var(--warning-border)' : 'var(--safe-border)'}`,
                    textTransform: 'uppercase', letterSpacing: '0.06em',
                  }}>
                    {pb.severity}
                  </span>
                </div>
                <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)', marginBottom: '10px', lineHeight: 1.5 }}>{pb.description}</div>
                <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                  {pb.actions.map((a: string) => (
                    <span key={a} style={{
                      fontSize: '0.65rem', padding: '3px 10px', borderRadius: '6px',
                      background: 'rgba(129,140,248,0.06)', color: 'var(--text-muted)',
                      fontFamily: 'var(--font-mono)', fontWeight: 600,
                      border: '1px solid var(--border)',
                    }}>{a}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Recent Executions */}
        <div className="card" style={{ padding: '22px', maxHeight: '500px', overflow: 'auto' }}>
          <h2 style={{
            fontSize: '0.72rem', fontWeight: 700, textTransform: 'uppercase',
            letterSpacing: '0.1em', color: 'var(--text-muted)', marginBottom: '18px',
            display: 'flex', alignItems: 'center', gap: '8px',
          }}>
            <div style={{
              width: 24, height: 24, borderRadius: 6,
              background: 'rgba(129,140,248,0.08)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <Clock size={12} color="var(--accent-indigo)" />
            </div>
            Recent Executions
          </h2>
          {executions.length === 0 ? (
            <div style={{
              color: 'var(--text-muted)', fontSize: '0.85rem', textAlign: 'center',
              padding: '40px 0', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '10px',
            }}>
              <div style={{
                width: 44, height: 44, borderRadius: 12,
                background: 'rgba(129,140,248,0.06)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <Clock size={20} color="var(--text-muted)" />
              </div>
              No playbooks triggered yet
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {executions.map((exec, i) => (
                <div key={i} className="slide-in" style={{
                  padding: '14px', borderRadius: 'var(--radius-sm)',
                  border: `1px solid ${exec.severity === 'critical' ? 'var(--danger-border)' : 'var(--warning-border)'}`,
                  background: exec.severity === 'critical' ? 'rgba(248,113,113,0.04)' : 'rgba(251,191,36,0.04)',
                  animationDelay: `${i * 40}ms`,
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                    <span style={{ fontSize: '0.78rem', fontWeight: 800, fontFamily: 'var(--font-mono)' }}>
                      {exec.incident_id}
                    </span>
                    <span style={{
                      fontSize: '0.62rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)',
                    }}>
                      {new Date(exec.executed_at).toLocaleTimeString()}
                    </span>
                  </div>
                  <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginBottom: '8px' }}>
                    {exec.playbook_name} · {exec.event_process} (score {exec.event_score?.toFixed(0)})
                  </div>
                  <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                    {exec.actions?.map((a: any, j: number) => (
                      <div key={j} style={{
                        display: 'flex', alignItems: 'center', gap: '4px',
                        fontSize: '0.64rem', padding: '4px 10px', borderRadius: '6px',
                        background: 'rgba(0,0,0,0.2)', fontFamily: 'var(--font-mono)',
                        border: '1px solid var(--border)',
                      }}>
                        <ChevronRight size={10} /> {a.action}: {a.target}
                        {a.action_id && (
                          <button onClick={() => handleUndo(a.action_id)}
                            style={{
                              marginLeft: '4px', padding: '2px 8px', borderRadius: '4px',
                              border: '1px solid rgba(251,191,36,0.2)', background: 'rgba(251,191,36,0.08)',
                              color: 'var(--warning)', cursor: 'pointer', fontSize: '0.6rem',
                              display: 'flex', alignItems: 'center', gap: '3px', fontWeight: 700,
                            }}>
                            <RotateCcw size={8} /> Undo
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
