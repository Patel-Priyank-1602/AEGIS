import { useState, useEffect } from 'react'
import { Shield, RefreshCw, Database, AlertTriangle, Plus, Search, Globe, Hash, Link, CheckCircle, XCircle } from 'lucide-react'
import { api } from '../services/api'

export default function ThreatIntel() {
  const [stats, setStats] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [addForm, setAddForm] = useState({ ioc_type: 'ip', value: '', critical: false })
  const [checkIp, setCheckIp] = useState('')
  const [checkResult, setCheckResult] = useState<any>(null)

  useEffect(() => {
    loadStats()
    const interval = setInterval(loadStats, 30000)
    return () => clearInterval(interval)
  }, [])

  const loadStats = async () => {
    try {
      const data = await api.getThreatIntelStats()
      setStats(data)
    } catch (e) { console.error(e) }
    finally { setLoading(false) }
  }

  const handleRefresh = async () => {
    setRefreshing(true)
    try {
      const data = await api.refreshThreatFeeds()
      setStats(data)
    } catch (e) { console.error(e) }
    finally { setRefreshing(false) }
  }

  const handleAddIOC = async () => {
    if (!addForm.value) return
    try {
      await api.addCustomIOC(addForm)
      setAddForm({ ...addForm, value: '' })
      loadStats()
    } catch (e) { console.error(e) }
  }

  const handleCheck = async () => {
    if (!checkIp) return
    try {
      const result = await api.checkIP(checkIp)
      setCheckResult(result)
    } catch (e) { console.error(e) }
  }

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{
              width: 36, height: 36, borderRadius: 10,
              background: 'rgba(248,113,113,0.1)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <Shield size={20} color="#f87171" />
            </div>
            Threat Intelligence
          </h1>
          <p className="page-subtitle">Live IOC feeds from Abuse.ch, URLhaus, and custom sources</p>
        </div>
        <button className="btn btn-primary" onClick={handleRefresh} disabled={refreshing}>
          <RefreshCw size={14} className={refreshing ? 'spin' : ''} />
          {refreshing ? 'Refreshing...' : 'Refresh Feeds'}
        </button>
      </div>

      {/* Stats Grid */}
      <div className="grid-4" style={{ marginBottom: '24px' }}>
        {[
          { label: 'Total IOCs', icon: Database, value: stats?.total_iocs?.toLocaleString() || '—', color: 'var(--accent)', bg: 'rgba(6,214,160,0.06)' },
          { label: 'Malicious IPs', icon: Globe, value: stats?.ip_count?.toLocaleString() || '—', color: 'var(--danger)', bg: 'rgba(248,113,113,0.06)' },
          { label: 'Malicious Domains', icon: Link, value: stats?.domain_count?.toLocaleString() || '—', color: 'var(--warning)', bg: 'rgba(251,191,36,0.06)' },
          { label: 'Critical IPs', icon: AlertTriangle, value: stats?.critical_ips || '—', color: 'var(--danger)', bg: 'rgba(248,113,113,0.06)' },
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
        {/* Feed Sources */}
        <div className="card" style={{ padding: '22px' }}>
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
              <Database size={12} color="var(--accent-indigo)" />
            </div>
            Active Feed Sources
          </h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {stats?.sources && Object.entries(stats.sources).map(([source, count]: [string, any]) => (
              <div key={source} style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                padding: '14px 16px', borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--border)', background: 'rgba(255,255,255,0.015)',
                transition: 'all 0.2s',
              }}>
                <div>
                  <div style={{ fontSize: '0.85rem', fontWeight: 700, textTransform: 'capitalize', marginBottom: '2px' }}>
                    {source.replace(/_/g, ' ')}
                  </div>
                  <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
                    {source === 'feodo_tracker' ? 'abuse.ch C2 IP Blocklist' :
                     source === 'urlhaus' ? 'abuse.ch Malicious URLs' :
                     source === 'sslbl' ? 'abuse.ch SSL Blacklist' : 'Built-in high-confidence IOCs'}
                  </div>
                </div>
                <span style={{
                  fontFamily: 'var(--font-mono)', fontSize: '0.76rem', fontWeight: 800,
                  padding: '5px 14px', borderRadius: '100px',
                  background: 'rgba(6,214,160,0.08)', color: 'var(--safe)',
                  border: '1px solid rgba(6,214,160,0.12)',
                }}>
                  {(count as number).toLocaleString()} IOCs
                </span>
              </div>
            ))}
          </div>
          <div style={{
            marginTop: '16px', fontSize: '0.68rem', color: 'var(--text-muted)',
            padding: '8px 12px', borderRadius: 'var(--radius-sm)',
            background: 'rgba(255,255,255,0.015)', border: '1px solid var(--border)',
            fontFamily: 'var(--font-mono)',
          }}>
            Last updated: {stats?.last_update ? new Date(stats.last_update).toLocaleString() : 'Never'} · 
            Bloom filter: {stats?.bloom_size_kb || '—'}KB RAM
          </div>
        </div>

        {/* Tools Panel */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* IP Check */}
          <div className="card" style={{ padding: '22px' }}>
            <h3 style={{
              fontSize: '0.72rem', fontWeight: 700, textTransform: 'uppercase',
              letterSpacing: '0.1em', color: 'var(--text-muted)', marginBottom: '14px',
              display: 'flex', alignItems: 'center', gap: '8px',
            }}>
              <div style={{
                width: 24, height: 24, borderRadius: 6,
                background: 'rgba(129,140,248,0.08)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <Search size={12} color="var(--accent-indigo)" />
              </div>
              Check IP
            </h3>
            <div style={{ display: 'flex', gap: '8px' }}>
              <input type="text" value={checkIp} onChange={e => setCheckIp(e.target.value)}
                placeholder="e.g. 45.33.32.156"
                className="input"
                style={{ fontFamily: 'var(--font-mono)', fontSize: '0.84rem' }}
                onKeyDown={e => e.key === 'Enter' && handleCheck()}
              />
              <button className="btn btn-primary" onClick={handleCheck} style={{ padding: '10px 18px', flexShrink: 0 }}>
                Check
              </button>
            </div>
            {checkResult && (
              <div style={{
                marginTop: '12px', padding: '14px', borderRadius: 'var(--radius-sm)',
                border: `1px solid ${checkResult.ioc_matched ? 'var(--danger-border)' : 'var(--safe-border)'}`,
                background: checkResult.ioc_matched ? 'var(--danger-bg)' : 'var(--safe-bg)',
                fontSize: '0.8rem',
                display: 'flex', alignItems: 'center', gap: '8px',
              }}>
                {checkResult.ioc_matched ? (
                  <>
                    <XCircle size={16} color="var(--danger)" />
                    <span style={{ color: 'var(--danger)', fontWeight: 700 }}>
                      MATCH — {checkResult.ioc_confidence} confidence ({checkResult.ioc_count} hit{checkResult.ioc_count > 1 ? 's' : ''})
                    </span>
                  </>
                ) : (
                  <>
                    <CheckCircle size={16} color="var(--safe)" />
                    <span style={{ color: 'var(--safe)', fontWeight: 600 }}>Clean — no IOC match</span>
                  </>
                )}
              </div>
            )}
          </div>

          {/* Add Custom IOC */}
          <div className="card" style={{ padding: '22px' }}>
            <h3 style={{
              fontSize: '0.72rem', fontWeight: 700, textTransform: 'uppercase',
              letterSpacing: '0.1em', color: 'var(--text-muted)', marginBottom: '14px',
              display: 'flex', alignItems: 'center', gap: '8px',
            }}>
              <div style={{
                width: 24, height: 24, borderRadius: 6,
                background: 'rgba(129,140,248,0.08)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <Plus size={12} color="var(--accent-indigo)" />
              </div>
              Add Custom IOC
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              <select value={addForm.ioc_type} onChange={e => setAddForm({ ...addForm, ioc_type: e.target.value })}
                className="input" style={{ cursor: 'pointer' }}>
                <option value="ip">IP Address</option>
                <option value="domain">Domain</option>
                <option value="hash">File Hash</option>
                <option value="url">URL</option>
              </select>
              <input type="text" value={addForm.value} onChange={e => setAddForm({ ...addForm, value: e.target.value })}
                placeholder="Enter IOC value..."
                className="input"
                style={{ fontFamily: 'var(--font-mono)', fontSize: '0.84rem' }}
              />
              <label style={{
                display: 'flex', alignItems: 'center', gap: '8px',
                fontSize: '0.78rem', color: 'var(--text-muted)', cursor: 'pointer',
                padding: '4px 0',
              }}>
                <input type="checkbox" checked={addForm.critical}
                  onChange={e => setAddForm({ ...addForm, critical: e.target.checked })}
                  style={{ accentColor: 'var(--accent-indigo)' }}
                />
                Mark as critical (exact match, no bloom filter)
              </label>
              <button className="btn btn-primary" onClick={handleAddIOC} style={{ marginTop: '4px' }}>
                <Plus size={14} /> Add IOC
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
