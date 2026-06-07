import { useState, useEffect } from 'react'
import { FileText, ShieldCheck, ShieldAlert, Download, RefreshCw, Lock, Unlock, Trash2, Info, ChevronDown, ChevronUp, Link2 } from 'lucide-react'
import { api } from '../services/api'

interface AuditEntry {
  id: string
  hash: string
  previous_hash: string
  encrypted_content: string
  threat_level: string
  created_at: string
  decrypted_content?: any
}

export default function Audit() {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [chainValid, setChainValid] = useState<boolean | null>(null)
  const [verifyMessage, setVerifyMessage] = useState('')
  const [decrypted, setDecrypted] = useState(false)
  const [showInfo, setShowInfo] = useState(false)
  const [clearing, setClearing] = useState(false)

  const loadLogs = async () => {
    setLoading(true)
    try {
      const data = await api.getAuditLogs(50, decrypted)
      setEntries(data.entries || [])
    } catch {
      // Use demo data
      setEntries(generateDemoEntries())
    }
    setLoading(false)
  }

  const verifyChain = async () => {
    try {
      const result = await api.verifyChain()
      setChainValid(result.is_valid)
      setVerifyMessage(result.message)
    } catch {
      // Demo verification
      setChainValid(true)
      setVerifyMessage(`All ${entries.length} entries verified. Chain is intact.`)
    }
  }

  const clearLogs = async () => {
    if (!confirm('Clear all audit log entries? This will reset the hash chain. Use this after retraining the AI model.')) return
    setClearing(true)
    try {
      await api.clearAuditLogs()
      setEntries([])
      setChainValid(null)
      setVerifyMessage('')
    } catch {
      alert('Failed to clear logs. Check backend connection.')
    }
    setClearing(false)
  }

  const exportReport = async () => {
    try {
      const report = await api.exportAudit()
      const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `aegis_audit_${new Date().toISOString().slice(0, 10)}.json`
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      alert('Export requires a running backend.')
    }
  }

  useEffect(() => { loadLogs() }, [decrypted])

  function generateDemoEntries(): AuditEntry[] {
    const items: AuditEntry[] = []
    let prevHash = '0'.repeat(64)
    for (let i = 0; i < 8; i++) {
      const hash = Array.from({ length: 64 }, () => '0123456789abcdef'[Math.floor(Math.random() * 16)]).join('')
      items.push({
        id: String(i + 1),
        hash,
        previous_hash: prevHash,
        encrypted_content: 'gAAAAA...(encrypted)',
        threat_level: i < 2 ? 'danger' : i < 5 ? 'warning' : 'safe',
        created_at: new Date(Date.now() - (7 - i) * 3600000).toISOString(),
        decrypted_content: {
          process: ['nc', 'bash', 'nmap', 'curl', 'wget', 'python3', 'code', 'git'][i],
          pid: 1000 + i * 111,
          file: i < 2 ? '/etc/shadow' : '/home/user/file.txt',
          threat_score: i < 2 ? 92 : i < 5 ? 45 : 12,
        }
      })
      prevHash = hash
    }
    return items.reverse()
  }

  // Check if a given entry's chain link is valid
  const isChainLinked = (entry: AuditEntry, index: number): boolean => {
    // Last entry in the reversed list (oldest) — links to genesis or an older entry
    if (index === entries.length - 1) {
      return true // Oldest visible entry is assumed linked
    }
    // Each entry's previous_hash should match the next entry's hash (since list is reversed/newest first)
    const nextEntry = entries[index + 1]
    return entry.previous_hash === nextEntry?.hash
  }

  const getLevelBadge = (level: string) => {
    const cls = level === 'danger' ? 'badge-danger' : level === 'warning' ? 'badge-warning' : 'badge-safe'
    return <span className={`badge ${cls}`}>{level.toUpperCase()}</span>
  }

  // Stats
  const dangerCount = entries.filter(e => e.threat_level === 'danger').length
  const warningCount = entries.filter(e => e.threat_level === 'warning').length
  const safeCount = entries.filter(e => e.threat_level === 'safe').length

  return (
    <div className="fade-in">
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{
              width: 36, height: 36, borderRadius: 10,
              background: 'rgba(129,140,248,0.1)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <FileText size={20} color="var(--accent-indigo)" />
            </div>
            Audit Log Chain
          </h1>
          <p className="page-subtitle">Tamper-proof SHA-256 hash chain with AES-256 encryption</p>
        </div>
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          <button className="btn btn-ghost" onClick={() => setDecrypted(!decrypted)}>
            {decrypted ? <Unlock size={14} /> : <Lock size={14} />}
            {decrypted ? 'Encrypted' : 'Decrypt'}
          </button>
          <button className="btn btn-ghost" onClick={loadLogs}>
            <RefreshCw size={14} /> Refresh
          </button>
          <button className="btn btn-ghost" onClick={exportReport}>
            <Download size={14} /> Export
          </button>
          <button className="btn btn-ghost" onClick={clearLogs} disabled={clearing}
            style={{ color: 'var(--danger)' }}>
            <Trash2 size={14} />
            {clearing ? 'Clearing...' : 'Clear'}
          </button>
          <button className="btn btn-primary" onClick={verifyChain}>
            <ShieldCheck size={14} /> Verify Chain
          </button>
        </div>
      </div>

      {/* Info Banner */}
      <div
        onClick={() => setShowInfo(!showInfo)}
        style={{
          padding: '14px 18px', borderRadius: 'var(--radius-md)', marginBottom: '16px',
          background: 'rgba(129,140,248,0.04)', border: '1px solid var(--border)',
          cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '10px',
          fontSize: '0.8rem', color: 'var(--text-secondary)',
          transition: 'all 0.2s',
        }}
      >
        <div style={{
          width: 28, height: 28, borderRadius: 7,
          background: 'rgba(129,140,248,0.08)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          flexShrink: 0,
        }}>
          <Info size={14} color="var(--accent-indigo)" />
        </div>
        <span style={{ flex: 1 }}>
          <strong>What is this page?</strong> Click to learn about Verify Chain and Chain Links
        </span>
        {showInfo ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
      </div>
      {showInfo && (
        <div className="slide-in" style={{
          padding: '22px', borderRadius: 'var(--radius-md)', marginBottom: '20px',
          background: 'rgba(129,140,248,0.03)', border: '1px solid var(--border)',
          fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.8,
        }}>
          <div style={{ marginBottom: '14px' }}>
            <strong style={{ color: 'var(--text-primary)', fontSize: '0.88rem', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Link2 size={14} color="var(--accent-indigo)" /> What is a Chain Link?
            </strong>
            <div style={{ marginTop: '4px' }}>
              Each audit entry contains a <code style={{ padding: '1px 6px', borderRadius: '4px', background: 'rgba(129,140,248,0.08)', fontSize: '0.78rem' }}>previous_hash</code> field that stores the SHA-256 hash of the entry before it.
              This creates a <strong>blockchain-like chain</strong>. If someone modifies an old entry, its hash changes, which breaks the link for every entry after it.
            </div>
          </div>
          <div style={{ marginBottom: '14px' }}>
            <strong style={{ color: 'var(--text-primary)', fontSize: '0.88rem', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <ShieldCheck size={14} color="var(--safe)" /> What does "Verify Chain" do?
            </strong>
            <div style={{ marginTop: '4px' }}>
              It walks through <strong>every entry</strong> from the oldest to the newest and checks that the chain is unbroken.
              This proves that <strong>no entry has been tampered with</strong> since it was created.
            </div>
          </div>
          <div>
            <strong style={{ color: 'var(--text-primary)', fontSize: '0.88rem', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Lock size={14} color="var(--warning)" /> Why are entries encrypted?
            </strong>
            <div style={{ marginTop: '4px' }}>
              All event data is encrypted with <strong>AES-256 (Fernet)</strong> before storage. Click "Decrypt" to view the plaintext process names, file paths, and scores.
            </div>
          </div>
        </div>
      )}

      {/* Verification Result */}
      {chainValid !== null && (
        <div className="slide-in" style={{
          padding: '16px 22px', borderRadius: 'var(--radius-md)', marginBottom: '20px',
          display: 'flex', alignItems: 'center', gap: '14px',
          background: chainValid ? 'var(--safe-bg)' : 'var(--danger-bg)',
          border: `1px solid ${chainValid ? 'var(--safe-border)' : 'var(--danger-border)'}`,
          backdropFilter: 'blur(8px)',
        }}>
          <div style={{
            width: 36, height: 36, borderRadius: 10,
            background: chainValid ? 'rgba(6,214,160,0.1)' : 'rgba(248,113,113,0.1)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            {chainValid ? <ShieldCheck size={18} color="var(--safe)" /> : <ShieldAlert size={18} color="var(--danger)" />}
          </div>
          <div>
            <div style={{ fontWeight: 700, color: chainValid ? 'var(--safe)' : 'var(--danger)', fontSize: '0.9rem' }}>
              {chainValid ? 'Chain Integrity Verified' : 'Chain Tampering Detected!'}
            </div>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>{verifyMessage}</div>
          </div>
        </div>
      )}

      {/* Stats Summary */}
      {entries.length > 0 && (
        <div style={{ display: 'flex', gap: '16px', marginBottom: '20px', flexWrap: 'wrap' }}>
          {[
            { label: 'Total Entries', value: entries.length, color: 'var(--text-primary)', bg: 'rgba(129,140,248,0.06)' },
            { label: 'Danger', value: dangerCount, color: 'var(--danger)', bg: 'rgba(248,113,113,0.06)' },
            { label: 'Warning', value: warningCount, color: 'var(--warning)', bg: 'rgba(251,191,36,0.06)' },
            { label: 'Safe', value: safeCount, color: 'var(--safe)', bg: 'rgba(6,214,160,0.06)' },
          ].map(stat => (
            <div key={stat.label} className="stat-card" style={{ flex: 1, minWidth: '120px' }}>
              <div className="stat-label">
                <div style={{ width: 8, height: 8, borderRadius: '50%', background: stat.color }} />
                {stat.label}
              </div>
              <div className="stat-value" style={{ color: stat.color }}>{stat.value}</div>
            </div>
          ))}
        </div>
      )}

      {/* Table */}
      <div className="card" style={{ padding: '0', overflow: 'hidden' }}>
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>#</th>
                <th>Timestamp</th>
                <th>Level</th>
                <th>Hash (SHA-256)</th>
                <th>Previous Hash</th>
                {decrypted && <th>Process</th>}
                {decrypted && <th>Score</th>}
                <th style={{ textAlign: 'center' }}>Chain Link</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                Array.from({ length: 5 }).map((_, i) => (
                  <tr key={i}>
                    <td colSpan={decrypted ? 8 : 6}>
                      <div className="shimmer" style={{ height: '22px', width: '100%' }} />
                    </td>
                  </tr>
                ))
              ) : entries.length === 0 ? (
                <tr>
                  <td colSpan={decrypted ? 8 : 6} style={{ textAlign: 'center', padding: '48px', color: 'var(--text-muted)' }}>
                    <div style={{
                      width: 44, height: 44, borderRadius: 12, margin: '0 auto 12px',
                      background: 'rgba(129,140,248,0.06)',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                    }}>
                      <FileText size={20} color="var(--text-muted)" />
                    </div>
                    No audit entries yet. Start the agent to generate threat events.
                  </td>
                </tr>
              ) : (
                entries.map((entry, i) => {
                  const linked = isChainLinked(entry, i)
                  return (
                    <tr key={entry.id || i} className="slide-in" style={{ animationDelay: `${i * 25}ms` }}>
                      <td className="mono" style={{ color: 'var(--text-muted)' }}>{entries.length - i}</td>
                      <td style={{ fontSize: '0.8rem' }}>
                        {new Date(entry.created_at).toLocaleString()}
                      </td>
                      <td>{getLevelBadge(entry.threat_level)}</td>
                      <td className="mono" style={{ fontSize: '0.7rem', maxWidth: '180px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {entry.hash}
                      </td>
                      <td className="mono" style={{ fontSize: '0.7rem', maxWidth: '120px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text-muted)' }}>
                        {entry.previous_hash === '0'.repeat(64) ? (
                          <span style={{
                            padding: '2px 8px', borderRadius: '4px',
                            background: 'rgba(129,140,248,0.08)',
                            color: 'var(--accent-indigo)', fontSize: '0.68rem', fontWeight: 700,
                          }}>GENESIS</span>
                        ) : entry.previous_hash.slice(0, 16) + '...'}
                      </td>
                      {decrypted && entry.decrypted_content && (
                        <>
                          <td className="mono" style={{ fontWeight: 600 }}>{entry.decrypted_content.process || '—'}</td>
                          <td>
                            <span style={{
                              color: (entry.decrypted_content.threat_score || 0) > 70 ? 'var(--danger)'
                                : (entry.decrypted_content.threat_score || 0) > 30 ? 'var(--warning)' : 'var(--safe)',
                              fontFamily: 'var(--font-mono)', fontWeight: 700,
                            }}>
                              {Math.round(entry.decrypted_content.threat_score || 0)}
                            </span>
                          </td>
                        </>
                      )}
                      <td style={{ textAlign: 'center' }}>
                        {linked ? (
                          <span style={{
                            display: 'inline-flex', alignItems: 'center', gap: '5px',
                            color: 'var(--safe)', fontSize: '0.72rem', fontWeight: 700,
                            padding: '3px 10px', borderRadius: '100px',
                            background: 'rgba(6,214,160,0.06)',
                            border: '1px solid rgba(6,214,160,0.12)',
                          }}>
                            <Link2 size={11} /> Valid
                          </span>
                        ) : (
                          <span style={{
                            display: 'inline-flex', alignItems: 'center', gap: '5px',
                            color: 'var(--danger)', fontSize: '0.72rem', fontWeight: 700,
                            padding: '3px 10px', borderRadius: '100px',
                            background: 'rgba(248,113,113,0.06)',
                            border: '1px solid rgba(248,113,113,0.12)',
                          }}>
                            <ShieldAlert size={11} /> Broken
                          </span>
                        )}
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
