import { useState, useEffect } from 'react'
import { Shield, RefreshCw, Database, AlertTriangle, Plus, Search, Globe, Hash, Link } from 'lucide-react'
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
            <Shield size={24} /> Threat Intelligence
          </h1>
          <p className="page-subtitle">Live IOC feeds from Abuse.ch, URLhaus, and custom sources</p>
        </div>
        <button className="btn btn-primary" onClick={handleRefresh} disabled={refreshing}
          style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <RefreshCw size={14} className={refreshing ? 'spin' : ''} />
          {refreshing ? 'Refreshing...' : 'Refresh Feeds'}
        </button>
      </div>

      {/* Stats Grid */}
      <div className="grid-4" style={{ marginBottom: '24px' }}>
        <div className="stat-card">
          <div className="stat-label"><Database size={12} style={{ marginRight: '4px', verticalAlign: 'middle' }} /> Total IOCs</div>
          <div className="stat-value" style={{ color: 'var(--accent)' }}>{stats?.total_iocs?.toLocaleString() || '—'}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label"><Globe size={12} style={{ marginRight: '4px', verticalAlign: 'middle' }} /> Malicious IPs</div>
          <div className="stat-value danger">{stats?.ip_count?.toLocaleString() || '—'}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label"><Link size={12} style={{ marginRight: '4px', verticalAlign: 'middle' }} /> Malicious Domains</div>
          <div className="stat-value warning">{stats?.domain_count?.toLocaleString() || '—'}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label"><AlertTriangle size={12} style={{ marginRight: '4px', verticalAlign: 'middle' }} /> Critical IPs</div>
          <div className="stat-value danger">{stats?.critical_ips || '—'}</div>
        </div>
      </div>

      <div className="grid-2-1">
        {/* Feed Sources */}
        <div className="card" style={{ padding: '20px' }}>
          <h2 style={{ fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: '16px' }}>
            <Database size={14} style={{ marginRight: '8px', verticalAlign: 'middle' }} />
            Active Feed Sources
          </h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {stats?.sources && Object.entries(stats.sources).map(([source, count]: [string, any]) => (
              <div key={source} style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                padding: '12px 16px', borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--border)', background: 'rgba(255,255,255,0.02)',
              }}>
                <div>
                  <div style={{ fontSize: '0.85rem', fontWeight: 600, textTransform: 'capitalize' }}>
                    {source.replace(/_/g, ' ')}
                  </div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                    {source === 'feodo_tracker' ? 'abuse.ch C2 IP Blocklist' :
                     source === 'urlhaus' ? 'abuse.ch Malicious URLs' :
                     source === 'sslbl' ? 'abuse.ch SSL Blacklist' : 'Built-in high-confidence IOCs'}
                  </div>
                </div>
                <span style={{
                  fontFamily: 'var(--font-mono)', fontSize: '0.8rem', fontWeight: 700,
                  padding: '4px 12px', borderRadius: '100px',
                  background: 'rgba(6,214,160,0.1)', color: 'var(--safe)',
                }}>
                  {(count as number).toLocaleString()} IOCs
                </span>
              </div>
            ))}
          </div>
          <div style={{ marginTop: '16px', fontSize: '0.7rem', color: 'var(--text-muted)' }}>
            Last updated: {stats?.last_update ? new Date(stats.last_update).toLocaleString() : 'Never'} · 
            Bloom filter: {stats?.bloom_size_kb || '—'}KB RAM
          </div>
        </div>

        {/* Tools Panel */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* IP Check */}
          <div className="card" style={{ padding: '20px' }}>
            <h3 style={{ fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: '12px' }}>
              <Search size={14} style={{ marginRight: '8px', verticalAlign: 'middle' }} />
              Check IP
            </h3>
            <div style={{ display: 'flex', gap: '8px' }}>
              <input type="text" value={checkIp} onChange={e => setCheckIp(e.target.value)}
                placeholder="e.g. 45.33.32.156"
                style={{
                  flex: 1, padding: '8px 12px', borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--border)', background: 'var(--bg-secondary)',
                  color: 'var(--text-primary)', fontSize: '0.85rem', fontFamily: 'var(--font-mono)',
                }}
                onKeyDown={e => e.key === 'Enter' && handleCheck()}
              />
              <button className="btn btn-primary" onClick={handleCheck} style={{ padding: '8px 16px' }}>
                Check
              </button>
            </div>
            {checkResult && (
              <div style={{
                marginTop: '12px', padding: '12px', borderRadius: 'var(--radius-sm)',
                border: `1px solid ${checkResult.ioc_matched ? 'var(--danger-border)' : 'var(--safe-border)'}`,
                background: checkResult.ioc_matched ? 'var(--danger-bg)' : 'var(--safe-bg)',
                fontSize: '0.8rem',
              }}>
                {checkResult.ioc_matched ? (
                  <span style={{ color: 'var(--danger)', fontWeight: 700 }}>
                    ⚠️ MATCH — {checkResult.ioc_confidence} confidence ({checkResult.ioc_count} hit{checkResult.ioc_count > 1 ? 's' : ''})
                  </span>
                ) : (
                  <span style={{ color: 'var(--safe)' }}>✓ Clean — no IOC match</span>
                )}
              </div>
            )}
          </div>

          {/* Add Custom IOC */}
          <div className="card" style={{ padding: '20px' }}>
            <h3 style={{ fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: '12px' }}>
              <Plus size={14} style={{ marginRight: '8px', verticalAlign: 'middle' }} />
              Add Custom IOC
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <select value={addForm.ioc_type} onChange={e => setAddForm({ ...addForm, ioc_type: e.target.value })}
                style={{
                  padding: '8px 12px', borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--border)', background: 'var(--bg-secondary)',
                  color: 'var(--text-primary)', fontSize: '0.85rem',
                }}>
                <option value="ip">IP Address</option>
                <option value="domain">Domain</option>
                <option value="hash">File Hash</option>
                <option value="url">URL</option>
              </select>
              <input type="text" value={addForm.value} onChange={e => setAddForm({ ...addForm, value: e.target.value })}
                placeholder="Enter IOC value..."
                style={{
                  padding: '8px 12px', borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--border)', background: 'var(--bg-secondary)',
                  color: 'var(--text-primary)', fontSize: '0.85rem', fontFamily: 'var(--font-mono)',
                }}
              />
              <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                <input type="checkbox" checked={addForm.critical}
                  onChange={e => setAddForm({ ...addForm, critical: e.target.checked })} />
                Mark as critical (exact match, no bloom filter)
              </label>
              <button className="btn btn-primary" onClick={handleAddIOC} style={{ marginTop: '4px' }}>
                Add IOC
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
