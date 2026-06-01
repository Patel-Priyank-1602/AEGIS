import { useState } from 'react'
import { Settings as SettingsIcon, Cpu, Shield, Database, Globe, Save, RotateCcw } from 'lucide-react'

export default function SettingsPage() {
  const [settings, setSettings] = useState({
    warningThreshold: 70,
    dangerThreshold: 85,
    batchSize: 50,
    sendInterval: 1.0,
    autoKill: false,
    notifications: true,
    auditRetention: 30,
    backendUrl: 'http://localhost:8000',
    wsUrl: 'ws://localhost:8000',
  })

  const [saved, setSaved] = useState(false)

  const handleSave = () => {
    localStorage.setItem('aegis_settings', JSON.stringify(settings))
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  const handleReset = () => {
    setSettings({
      warningThreshold: 70,
      dangerThreshold: 85,
      batchSize: 50,
      sendInterval: 1.0,
      autoKill: false,
      notifications: true,
      auditRetention: 30,
      backendUrl: 'http://localhost:8000',
      wsUrl: 'ws://localhost:8000',
    })
  }

  const Section = ({ icon: Icon, title, children }: { icon: any; title: string; children: React.ReactNode }) => (
    <div className="card" style={{ marginBottom: '20px' }}>
      <h3 style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '1rem', fontWeight: 600, marginBottom: '20px' }}>
        <Icon size={18} color="var(--accent-indigo)" />
        {title}
      </h3>
      <div style={{ display: 'grid', gap: '16px' }}>{children}</div>
    </div>
  )

  const Field = ({ label, desc, children }: { label: string; desc?: string; children: React.ReactNode }) => (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '24px' }}>
      <div>
        <div style={{ fontSize: '0.875rem', fontWeight: 500 }}>{label}</div>
        {desc && <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '2px' }}>{desc}</div>}
      </div>
      {children}
    </div>
  )

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <SettingsIcon size={24} />
            Settings
          </h1>
          <p className="page-subtitle">Configure AEGIS monitoring behavior and thresholds</p>
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button className="btn btn-ghost" onClick={handleReset}>
            <RotateCcw size={14} /> Reset
          </button>
          <button className="btn btn-primary" onClick={handleSave}>
            <Save size={14} /> {saved ? '✓ Saved!' : 'Save Settings'}
          </button>
        </div>
      </div>

      <Section icon={Cpu} title="AI Engine">
        <Field label="Warning Threshold" desc="Events above this score trigger warnings">
          <input
            type="range" min={20} max={90} value={settings.warningThreshold}
            onChange={e => setSettings(s => ({ ...s, warningThreshold: +e.target.value }))}
            style={{ width: '200px', accentColor: 'var(--warning)' }}
          />
          <span className="mono" style={{ color: 'var(--warning)', width: '40px', textAlign: 'right' }}>{settings.warningThreshold}</span>
        </Field>
        <Field label="Danger Threshold" desc="Events above this score trigger critical alerts">
          <input
            type="range" min={50} max={99} value={settings.dangerThreshold}
            onChange={e => setSettings(s => ({ ...s, dangerThreshold: +e.target.value }))}
            style={{ width: '200px', accentColor: 'var(--danger)' }}
          />
          <span className="mono" style={{ color: 'var(--danger)', width: '40px', textAlign: 'right' }}>{settings.dangerThreshold}</span>
        </Field>
      </Section>

      <Section icon={Shield} title="Security">
        <Field label="Auto-Kill Dangerous Processes" desc="Automatically terminate processes with danger-level scores">
          <label style={{ position: 'relative', display: 'inline-block', width: '44px', height: '24px' }}>
            <input
              type="checkbox" checked={settings.autoKill}
              onChange={e => setSettings(s => ({ ...s, autoKill: e.target.checked }))}
              style={{ opacity: 0, width: 0, height: 0 }}
            />
            <span style={{
              position: 'absolute', cursor: 'pointer', top: 0, left: 0, right: 0, bottom: 0,
              background: settings.autoKill ? 'var(--danger)' : 'var(--bg-tertiary)',
              borderRadius: '12px', transition: '0.3s',
            }}>
              <span style={{
                position: 'absolute', height: '18px', width: '18px',
                left: settings.autoKill ? '23px' : '3px', bottom: '3px',
                background: 'white', borderRadius: '50%', transition: '0.3s',
              }} />
            </span>
          </label>
        </Field>
        <Field label="Browser Notifications" desc="Show desktop notifications for threat alerts">
          <label style={{ position: 'relative', display: 'inline-block', width: '44px', height: '24px' }}>
            <input
              type="checkbox" checked={settings.notifications}
              onChange={e => setSettings(s => ({ ...s, notifications: e.target.checked }))}
              style={{ opacity: 0, width: 0, height: 0 }}
            />
            <span style={{
              position: 'absolute', cursor: 'pointer', top: 0, left: 0, right: 0, bottom: 0,
              background: settings.notifications ? 'var(--safe)' : 'var(--bg-tertiary)',
              borderRadius: '12px', transition: '0.3s',
            }}>
              <span style={{
                position: 'absolute', height: '18px', width: '18px',
                left: settings.notifications ? '23px' : '3px', bottom: '3px',
                background: 'white', borderRadius: '50%', transition: '0.3s',
              }} />
            </span>
          </label>
        </Field>
      </Section>

      <Section icon={Database} title="Data & Storage">
        <Field label="Audit Log Retention" desc="Number of days to keep audit logs">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <input
              className="input"
              type="number" min={7} max={365} value={settings.auditRetention}
              onChange={e => setSettings(s => ({ ...s, auditRetention: +e.target.value }))}
              style={{ width: '80px', textAlign: 'center' }}
            />
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>days</span>
          </div>
        </Field>
        <Field label="Agent Batch Size" desc="Events batched before sending to backend">
          <input
            className="input"
            type="number" min={10} max={200} value={settings.batchSize}
            onChange={e => setSettings(s => ({ ...s, batchSize: +e.target.value }))}
            style={{ width: '80px', textAlign: 'center' }}
          />
        </Field>
      </Section>

      <Section icon={Globe} title="Connection">
        <Field label="Backend URL" desc="FastAPI backend server address">
          <input
            className="input"
            type="url" value={settings.backendUrl}
            onChange={e => setSettings(s => ({ ...s, backendUrl: e.target.value }))}
            style={{ width: '280px' }}
          />
        </Field>
        <Field label="WebSocket URL" desc="Real-time event stream endpoint">
          <input
            className="input"
            type="url" value={settings.wsUrl}
            onChange={e => setSettings(s => ({ ...s, wsUrl: e.target.value }))}
            style={{ width: '280px' }}
          />
        </Field>
      </Section>
    </div>
  )
}
