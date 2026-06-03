import { useState, useEffect } from 'react'
import { Zap, Play, RotateCcw, AlertTriangle, Shield, Clock, ChevronRight } from 'lucide-react'
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
    s === 'critical' ? 'var(--danger-bg)' : s === 'high' ? 'var(--warning-bg)' : 'var(--safe-bg)'

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <Zap size={24} /> Automated Playbooks
          </h1>
          <p className="page-subtitle">Automated response actions with full undo capability</p>
        </div>
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          <div style={{
            padding: '6px 14px', borderRadius: '100px', fontSize: '0.75rem', fontWeight: 600,
            background: stats?.enabled ? 'var(--safe-bg)' : 'var(--danger-bg)',
            color: stats?.enabled ? 'var(--safe)' : 'var(--danger)',
            border: `1px solid ${stats?.enabled ? 'var(--safe-border)' : 'var(--danger-border)'}`,
          }}>
            {stats?.enabled ? '● Active' : '○ Disabled'}
          </div>
          <button className="btn btn-ghost" onClick={handleToggle}>
            {stats?.enabled ? 'Disable' : 'Enable'}
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid-4" style={{ marginBottom: '24px' }}>
        <div className="stat-card">
          <div className="stat-label"><Play size={12} style={{ marginRight: '4px', verticalAlign: 'middle' }} /> Executions</div>
          <div className="stat-value" style={{ color: 'var(--accent)' }}>{stats?.total_executions || 0}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label"><Zap size={12} style={{ marginRight: '4px', verticalAlign: 'middle' }} /> Actions Taken</div>
          <div className="stat-value warning">{stats?.total_actions || 0}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label"><Shield size={12} style={{ marginRight: '4px', verticalAlign: 'middle' }} /> IPs Blocked</div>
          <div className="stat-value danger">{stats?.blocked_ips || 0}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label"><AlertTriangle size={12} style={{ marginRight: '4px', verticalAlign: 'middle' }} /> JWTs Revoked</div>
          <div className="stat-value" style={{ color: 'var(--text-primary)' }}>{stats?.denied_jwts || 0}</div>
        </div>
      </div>

      <div className="grid-2-1">
        {/* Playbook Definitions */}
        <div className="card" style={{ padding: '20px' }}>
          <h2 style={{ fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: '16px' }}>
            Configured Playbooks
          </h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {playbooks && Object.entries(playbooks).map(([id, pb]: [string, any]) => (
              <div key={id} style={{
                padding: '14px 16px', borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--border)', background: 'rgba(255,255,255,0.02)',
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <span style={{ fontWeight: 600, fontSize: '0.85rem' }}>{pb.name}</span>
                  <span style={{
                    fontSize: '0.65rem', fontWeight: 700, padding: '2px 10px', borderRadius: '100px',
                    background: severityBg(pb.severity), color: severityColor(pb.severity),
                  }}>
                    {pb.severity.toUpperCase()}
                  </span>
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '8px' }}>{pb.description}</div>
                <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                  {pb.actions.map((a: string) => (
                    <span key={a} style={{
                      fontSize: '0.65rem', padding: '2px 8px', borderRadius: '4px',
                      background: 'var(--bg-secondary)', color: 'var(--text-muted)',
                      fontFamily: 'var(--font-mono)',
                    }}>{a}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Recent Executions */}
        <div className="card" style={{ padding: '20px', maxHeight: '500px', overflow: 'auto' }}>
          <h2 style={{ fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: '16px' }}>
            <Clock size={14} style={{ marginRight: '8px', verticalAlign: 'middle' }} />
            Recent Executions
          </h2>
          {executions.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem', textAlign: 'center', padding: '40px 0' }}>
              No playbooks triggered yet
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {executions.map((exec, i) => (
                <div key={i} style={{
                  padding: '12px', borderRadius: 'var(--radius-sm)',
                  border: `1px solid ${exec.severity === 'critical' ? 'var(--danger-border)' : 'var(--warning-border)'}`,
                  background: exec.severity === 'critical' ? 'var(--danger-bg)' : 'var(--warning-bg)',
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                    <span style={{ fontSize: '0.8rem', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
                      {exec.incident_id}
                    </span>
                    <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>
                      {new Date(exec.executed_at).toLocaleTimeString()}
                    </span>
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '6px' }}>
                    {exec.playbook_name} · {exec.event_process} (score {exec.event_score?.toFixed(0)})
                  </div>
                  <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                    {exec.actions?.map((a: any, j: number) => (
                      <div key={j} style={{
                        display: 'flex', alignItems: 'center', gap: '4px',
                        fontSize: '0.65rem', padding: '3px 8px', borderRadius: '4px',
                        background: 'rgba(0,0,0,0.2)', fontFamily: 'var(--font-mono)',
                      }}>
                        <ChevronRight size={10} /> {a.action}: {a.target}
                        {a.action_id && (
                          <button onClick={() => handleUndo(a.action_id)}
                            style={{
                              marginLeft: '4px', padding: '1px 6px', borderRadius: '4px',
                              border: 'none', background: 'rgba(255,255,255,0.1)',
                              color: 'var(--warning)', cursor: 'pointer', fontSize: '0.6rem',
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
