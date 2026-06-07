import { useState } from 'react'
import { Settings as SettingsIcon, Cpu, Shield, Database, Globe, Save, RotateCcw, CheckCircle } from 'lucide-react'

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

  const Section = ({ icon: Icon, title, color, children }: { icon: any; title: string; color: string; children: React.ReactNode }) => (
    <div className="card" style={{ marginBottom: '20px' }}>
      <h3 style={{
        display: 'flex', alignItems: 'center', gap: '12px',
        fontSize: '1rem', fontWeight: 700, marginBottom: '22px',
      }}>
        <div style={{
          width: 32, height: 32, borderRadius: 9,
          background: `${color}12`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          border: `1px solid ${color}20`,
        }}>
          <Icon size={16} color={color} />
        </div>
        {title}
      </h3>
      <div style={{ display: 'grid', gap: '18px' }}>{children}</div>
    </div>
  )

  const Field = ({ label, desc, children }: { label: string; desc?: string; children: React.ReactNode }) => (
    <div style={{
      display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '24px',
      padding: '4px 0',
    }}>
      <div>
        <div style={{ fontSize: '0.88rem', fontWeight: 600 }}>{label}</div>
        {desc && <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginTop: '3px', lineHeight: 1.5 }}>{desc}</div>}
      </div>
      <div style={{ flexShrink: 0 }}>{children}</div>
    </div>
  )

  const Toggle = ({ checked, onChange, color }: { checked: boolean; onChange: (v: boolean) => void; color: string }) => (
    <label style={{ position: 'relative', display: 'inline-block', width: '48px', height: '26px', cursor: 'pointer' }}>
      <input type="checkbox" checked={checked} onChange={e => onChange(e.target.checked)} style={{ opacity: 0, width: 0, height: 0 }} />
      <span style={{
        position: 'absolute', cursor: 'pointer', top: 0, left: 0, right: 0, bottom: 0,
        background: checked ? color : 'var(--bg-tertiary)',
        borderRadius: '13px', transition: '0.3s',
        border: `1px solid ${checked ? 'transparent' : 'var(--border)'}`,
        boxShadow: checked ? `0 0 12px ${color}40` : 'none',
      }}>
        <span style={{
          position: 'absolute', height: '20px', width: '20px',
          left: checked ? '25px' : '3px', bottom: '2px',
          background: 'white', borderRadius: '50%', transition: '0.3s',
          boxShadow: '0 1px 4px rgba(0,0,0,0.2)',
        }} />
      </span>
    </label>
  )

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{
              width: 36, height: 36, borderRadius: 10,
              background: 'rgba(129,140,248,0.1)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <SettingsIcon size={20} color="var(--accent-indigo)" />
            </div>
            Settings
          </h1>
          <p className="page-subtitle">Configure AEGIS monitoring behavior and thresholds</p>
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button className="btn btn-ghost" onClick={handleReset}>
            <RotateCcw size={14} /> Reset
          </button>
          <button className="btn btn-primary" onClick={handleSave}>
            {saved ? <CheckCircle size={14} /> : <Save size={14} />}
            {saved ? 'Saved!' : 'Save Settings'}
          </button>
        </div>
      </div>

      <Section icon={Cpu} title="AI Engine" color="#818cf8">
        <Field label="Warning Threshold" desc="Events above this score trigger warnings">
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <input
              type="range" min={20} max={90} value={settings.warningThreshold}
              onChange={e => setSettings(s => ({ ...s, warningThreshold: +e.target.value }))}
              style={{ width: '180px', accentColor: 'var(--warning)' }}
            />
            <span style={{
              fontFamily: 'var(--font-mono)', fontWeight: 800, color: 'var(--warning)',
              width: '36px', textAlign: 'right', fontSize: '0.9rem',
            }}>{settings.warningThreshold}</span>
          </div>
        </Field>
        <Field label="Danger Threshold" desc="Events above this score trigger critical alerts">
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <input
              type="range" min={50} max={99} value={settings.dangerThreshold}
              onChange={e => setSettings(s => ({ ...s, dangerThreshold: +e.target.value }))}
              style={{ width: '180px', accentColor: 'var(--danger)' }}
            />
            <span style={{
              fontFamily: 'var(--font-mono)', fontWeight: 800, color: 'var(--danger)',
              width: '36px', textAlign: 'right', fontSize: '0.9rem',
            }}>{settings.dangerThreshold}</span>
          </div>
        </Field>
      </Section>

      <Section icon={Shield} title="Security" color="#f87171">
        <Field label="Auto-Kill Dangerous Processes" desc="Automatically terminate processes with danger-level scores">
          <Toggle checked={settings.autoKill} onChange={v => setSettings(s => ({ ...s, autoKill: v }))} color="var(--danger)" />
        </Field>
        <Field label="Browser Notifications" desc="Show desktop notifications for threat alerts">
          <Toggle checked={settings.notifications} onChange={v => setSettings(s => ({ ...s, notifications: v }))} color="var(--safe)" />
        </Field>
      </Section>

      <Section icon={Database} title="Data & Storage" color="#fbbf24">
        <Field label="Audit Log Retention" desc="Number of days to keep audit logs">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <input
              className="input"
              type="number" min={7} max={365} value={settings.auditRetention}
              onChange={e => setSettings(s => ({ ...s, auditRetention: +e.target.value }))}
              style={{ width: '80px', textAlign: 'center' }}
            />
            <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)', fontWeight: 500 }}>days</span>
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

      <Section icon={Globe} title="Connection" color="#06d6a0">
        <Field label="Backend URL" desc="FastAPI backend server address">
          <input
            className="input"
            type="url" value={settings.backendUrl}
            onChange={e => setSettings(s => ({ ...s, backendUrl: e.target.value }))}
            style={{ width: '280px', fontFamily: 'var(--font-mono)', fontSize: '0.84rem' }}
          />
        </Field>
        <Field label="WebSocket URL" desc="Real-time event stream endpoint">
          <input
            className="input"
            type="url" value={settings.wsUrl}
            onChange={e => setSettings(s => ({ ...s, wsUrl: e.target.value }))}
            style={{ width: '280px', fontFamily: 'var(--font-mono)', fontSize: '0.84rem' }}
          />
        </Field>
      </Section>
    </div>
  )
}
