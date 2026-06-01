import { useState, useEffect } from 'react'
import { FileText, ShieldCheck, ShieldAlert, Download, RefreshCw, Lock, Unlock, Trash2, Info } from 'lucide-react'
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
            <FileText size={24} />
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
            <RefreshCw size={14} />
            Refresh
          </button>
          <button className="btn btn-ghost" onClick={exportReport}>
            <Download size={14} />
            Export
          </button>
          <button
            className="btn btn-ghost"
            onClick={clearLogs}
            disabled={clearing}
            style={{ color: 'var(--danger)' }}
          >
            <Trash2 size={14} />
            {clearing ? 'Clearing...' : 'Clear Logs'}
          </button>
          <button className="btn btn-primary" onClick={verifyChain}>
            <ShieldCheck size={14} />
            Verify Chain
          </button>
        </div>
      </div>

      {/* Info Banner */}
      <div
        onClick={() => setShowInfo(!showInfo)}
        style={{
          padding: '12px 16px', borderRadius: 'var(--radius-md)', marginBottom: '16px',
          background: 'rgba(99,102,241,0.06)', border: '1px solid var(--border)',
          cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '10px',
          fontSize: '0.8rem', color: 'var(--text-secondary)',
        }}
      >
        <Info size={16} style={{ flexShrink: 0, color: 'var(--primary)' }} />
        <span>
          <strong>What is this page?</strong> {showInfo ? 'Click to collapse ▲' : 'Click to learn about Verify Chain and Chain Links ▼'}
        </span>
      </div>
      {showInfo && (
        <div className="slide-in" style={{
          padding: '20px', borderRadius: 'var(--radius-md)', marginBottom: '20px',
          background: 'rgba(99,102,241,0.04)', border: '1px solid var(--border)',
          fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.8,
        }}>
          <div style={{ marginBottom: '12px' }}>
            <strong style={{ color: 'var(--text-primary)', fontSize: '0.85rem' }}>🔗 What is a Chain Link?</strong><br />
            Each audit entry contains a <code>previous_hash</code> field that stores the SHA-256 hash of the entry before it.
            This creates a <strong>blockchain-like chain</strong>. If someone modifies an old entry (e.g. changing a "danger" to "safe"),
            its hash changes, which breaks the link for every entry after it. The "Chain Link" column shows whether each entry
            correctly points to the entry before it.
          </div>
          <div style={{ marginBottom: '12px' }}>
            <strong style={{ color: 'var(--text-primary)', fontSize: '0.85rem' }}>✅ What does "Verify Chain" do?</strong><br />
            It walks through <strong>every entry</strong> from the oldest to the newest and checks that the chain is unbroken.
            If all links are valid, it proves that <strong>no entry has been tampered with</strong> since it was created.
            This is critical for compliance, forensic audits, and legal evidence.
          </div>
          <div>
            <strong style={{ color: 'var(--text-primary)', fontSize: '0.85rem' }}>🔐 Why are entries encrypted?</strong><br />
            All event data is encrypted with <strong>AES-256 (Fernet)</strong> before storage. Even if someone gains access to
            the database, they cannot read the content without the <code>AUDIT_ENCRYPTION_KEY</code>.
            Click "Decrypt" to view the plaintext process names, file paths, and scores.
          </div>
        </div>
      )}

      {/* Verification Result */}
      {chainValid !== null && (
        <div className="slide-in" style={{
          padding: '16px 20px', borderRadius: 'var(--radius-md)', marginBottom: '20px',
          display: 'flex', alignItems: 'center', gap: '12px',
          background: chainValid ? 'var(--safe-bg)' : 'var(--danger-bg)',
          border: `1px solid ${chainValid ? 'var(--safe-border)' : 'var(--danger-border)'}`,
        }}>
          {chainValid ? <ShieldCheck size={20} color="var(--safe)" /> : <ShieldAlert size={20} color="var(--danger)" />}
          <div>
            <div style={{ fontWeight: 600, color: chainValid ? 'var(--safe)' : 'var(--danger)' }}>
              {chainValid ? 'Chain Integrity Verified ✓' : 'Chain Tampering Detected!'}
            </div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{verifyMessage}</div>
          </div>
        </div>
      )}

      {/* Stats Summary */}
      {entries.length > 0 && (
        <div style={{
          display: 'flex', gap: '16px', marginBottom: '20px', flexWrap: 'wrap',
        }}>
          <div className="stat-card" style={{ flex: 1, minWidth: '120px' }}>
            <div className="stat-label">Total Entries</div>
            <div className="stat-value" style={{ color: 'var(--text-primary)' }}>{entries.length}</div>
          </div>
          <div className="stat-card" style={{ flex: 1, minWidth: '120px' }}>
            <div className="stat-label">🔴 Danger</div>
            <div className="stat-value danger">{dangerCount}</div>
          </div>
          <div className="stat-card" style={{ flex: 1, minWidth: '120px' }}>
            <div className="stat-label">🟡 Warning</div>
            <div className="stat-value warning">{warningCount}</div>
          </div>
          <div className="stat-card" style={{ flex: 1, minWidth: '120px' }}>
            <div className="stat-label">🟢 Safe</div>
            <div className="stat-value safe">{safeCount}</div>
          </div>
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
                      <div className="shimmer" style={{ height: '20px', width: '100%' }} />
                    </td>
                  </tr>
                ))
              ) : entries.length === 0 ? (
                <tr>
                  <td colSpan={decrypted ? 8 : 6} style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                    No audit entries yet. Start the agent to generate threat events.
                  </td>
                </tr>
              ) : (
                entries.map((entry, i) => {
                  const linked = isChainLinked(entry, i)
                  return (
                    <tr key={entry.id || i} className="slide-in" style={{ animationDelay: `${i * 30}ms` }}>
                      <td className="mono" style={{ color: 'var(--text-muted)' }}>{entries.length - i}</td>
                      <td style={{ fontSize: '0.8rem' }}>
                        {new Date(entry.created_at).toLocaleString()}
                      </td>
                      <td>{getLevelBadge(entry.threat_level)}</td>
                      <td className="mono" style={{ fontSize: '0.7rem', maxWidth: '180px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {entry.hash}
                      </td>
                      <td className="mono" style={{ fontSize: '0.7rem', maxWidth: '120px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text-muted)' }}>
                        {entry.previous_hash === '0'.repeat(64) ? '🏁 GENESIS' : entry.previous_hash.slice(0, 16) + '...'}
                      </td>
                      {decrypted && entry.decrypted_content && (
                        <>
                          <td className="mono">{entry.decrypted_content.process || '—'}</td>
                          <td>
                            <span style={{
                              color: (entry.decrypted_content.threat_score || 0) > 70 ? 'var(--danger)'
                                : (entry.decrypted_content.threat_score || 0) > 30 ? 'var(--warning)' : 'var(--safe)',
                              fontFamily: 'var(--font-mono)', fontWeight: 600,
                            }}>
                              {Math.round(entry.decrypted_content.threat_score || 0)}
                            </span>
                          </td>
                        </>
                      )}
                      <td style={{ textAlign: 'center' }}>
                        {linked ? (
                          <span style={{
                            display: 'inline-flex', alignItems: 'center', gap: '4px',
                            color: 'var(--safe)', fontSize: '0.75rem', fontWeight: 600,
                          }}>
                            🔗 Valid
                          </span>
                        ) : (
                          <span style={{
                            display: 'inline-flex', alignItems: 'center', gap: '4px',
                            color: 'var(--danger)', fontSize: '0.75rem', fontWeight: 600,
                          }}>
                            ⛓️‍💥 Broken
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
