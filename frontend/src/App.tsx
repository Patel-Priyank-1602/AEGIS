import { useState } from 'react'
import { Shield, Activity, FileText, Settings, LogOut, Zap, Globe, Cpu, Layers } from 'lucide-react'
import Dashboard from './pages/Dashboard'
import Login from './pages/Login'
import Audit from './pages/Audit'
import SettingsPage from './pages/Settings'
import ThreatIntel from './pages/ThreatIntel'
import Playbooks from './pages/Playbooks'
import Features from './pages/Features'

type Page = 'dashboard' | 'audit' | 'settings' | 'threat-intel' | 'playbooks' | 'features'

export default function App() {
  const [token, setToken] = useState<string | null>(localStorage.getItem('aegis_token'))
  const [username, setUsername] = useState<string>(localStorage.getItem('aegis_user') || '')
  const [currentPage, setCurrentPage] = useState<Page>('dashboard')

  const handleLogin = (newToken: string, user: string) => {
    setToken(newToken)
    setUsername(user)
    localStorage.setItem('aegis_token', newToken)
    localStorage.setItem('aegis_user', user)
  }

  const handleLogout = () => {
    setToken(null)
    setUsername('')
    localStorage.removeItem('aegis_token')
    localStorage.removeItem('aegis_user')
  }

  if (!token) {
    return <Login onLogin={handleLogin} />
  }

  const navItems = [
    { id: 'dashboard' as Page, label: 'Dashboard', icon: Activity },
    { id: 'threat-intel' as Page, label: 'Threat Intel', icon: Globe },
    { id: 'playbooks' as Page, label: 'Playbooks', icon: Zap },
    { id: 'features' as Page, label: 'All Features', icon: Layers },
    { id: 'audit' as Page, label: 'Audit Logs', icon: FileText },
    { id: 'settings' as Page, label: 'Settings', icon: Settings },
  ]

  return (
    <div className="app-layout">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="logo">
          <div className="logo-icon"><Shield size={18} /></div>
          <span className="logo-text">AEGIS</span>
          <span style={{
            fontSize: '0.5rem', fontWeight: 700, padding: '1px 5px', borderRadius: '4px',
            background: 'linear-gradient(135deg, rgba(99,102,241,0.3), rgba(6,214,160,0.3))',
            color: 'var(--accent)', marginLeft: '4px', letterSpacing: '0.05em',
          }}>v2</span>
        </div>

        <nav style={{ flex: 1 }}>
          {navItems.map(item => (
            <button
              key={item.id}
              className={`nav-item ${currentPage === item.id ? 'active' : ''}`}
              onClick={() => setCurrentPage(item.id)}
            >
              <item.icon size={18} />
              {item.label}
            </button>
          ))}
        </nav>

        <div style={{ borderTop: '1px solid var(--border)', paddingTop: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '8px 14px', marginBottom: '8px' }}>
            <div style={{
              width: '32px', height: '32px', borderRadius: '8px',
              background: 'var(--gradient-primary)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontWeight: 700, fontSize: '0.8rem'
            }}>
              {username.charAt(0).toUpperCase()}
            </div>
            <div>
              <div style={{ fontSize: '0.85rem', fontWeight: 600 }}>{username}</div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                <Zap size={10} /> ZK + PQC Auth
              </div>
            </div>
          </div>
          <button className="nav-item" onClick={handleLogout}>
            <LogOut size={18} />
            Log Out
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="main-content">
        {currentPage === 'dashboard' && <Dashboard />}
        {currentPage === 'threat-intel' && <ThreatIntel />}
        {currentPage === 'playbooks' && <Playbooks />}
        {currentPage === 'features' && <Features />}
        {currentPage === 'audit' && <Audit />}
        {currentPage === 'settings' && <SettingsPage />}
      </main>
    </div>
  )
}
