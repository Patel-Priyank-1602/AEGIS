import { useState, useEffect } from 'react'
import { Shield, Activity, FileText, Settings, LogOut, Zap, Globe, Layers, ChevronRight, Cpu } from 'lucide-react'
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
  const [pageTransition, setPageTransition] = useState(false)

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

  const navigateTo = (page: Page) => {
    if (page === currentPage) return
    setPageTransition(true)
    setTimeout(() => {
      setCurrentPage(page)
      setPageTransition(false)
    }, 150)
  }

  if (!token) {
    return <Login onLogin={handleLogin} />
  }

  const navItems = [
    { id: 'dashboard' as Page, label: 'Dashboard', icon: Activity, desc: 'Live monitoring' },
    { id: 'threat-intel' as Page, label: 'Threat Intel', icon: Globe, desc: 'IOC feeds' },
    { id: 'playbooks' as Page, label: 'Playbooks', icon: Zap, desc: 'Auto response' },
    { id: 'features' as Page, label: 'All Features', icon: Layers, desc: '10 capabilities' },
    { id: 'audit' as Page, label: 'Audit Logs', icon: FileText, desc: 'Hash chain' },
    { id: 'settings' as Page, label: 'Settings', icon: Settings, desc: 'Configuration' },
  ]

  const currentTime = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })

  return (
    <div className="app-layout">
      {/* Sidebar */}
      <aside className="sidebar">
        {/* Logo */}
        <div className="logo">
          <img src="/favicon.png" alt="AEGIS Logo" style={{ width: 32, height: 32, filter: 'drop-shadow(0 0 8px rgba(6,214,160,0.5))' }} />
          <span className="logo-text">AEGIS</span>
        </div>

        {/* System Status */}
        <div style={{
          padding: '10px 14px', marginBottom: '20px',
          borderRadius: 'var(--radius-sm)',
          background: 'rgba(6, 214, 160, 0.04)',
          border: '1px solid rgba(6, 214, 160, 0.08)',
        }}>
          <div style={{
            display: 'flex', alignItems: 'center', gap: '6px',
            fontSize: '0.65rem', fontWeight: 700, color: 'var(--safe)',
            textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '4px',
          }}>
            <div style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--safe)', animation: 'pulse 2s infinite' }} />
            System Online
          </div>
          <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
            {currentTime} · All services active
          </div>
        </div>

        {/* Navigation */}
        <nav style={{ flex: 1 }}>
          <div style={{
            fontSize: '0.6rem', fontWeight: 700, color: 'var(--text-muted)',
            textTransform: 'uppercase', letterSpacing: '0.12em',
            padding: '0 14px', marginBottom: '8px',
          }}>Navigation</div>
          {navItems.map(item => (
            <button
              key={item.id}
              className={`nav-item ${currentPage === item.id ? 'active' : ''}`}
              onClick={() => navigateTo(item.id)}
            >
              <div style={{
                width: 32, height: 32, borderRadius: 8,
                background: currentPage === item.id
                  ? 'rgba(129, 140, 248, 0.12)'
                  : 'rgba(255,255,255,0.03)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                transition: 'all 0.25s',
              }}>
                <item.icon size={16} />
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: '0.84rem' }}>{item.label}</div>
                <div style={{ fontSize: '0.62rem', color: 'var(--text-muted)', fontWeight: 400 }}>{item.desc}</div>
              </div>
              {currentPage === item.id && (
                <ChevronRight size={14} style={{ color: 'var(--accent-indigo)', opacity: 0.6 }} />
              )}
            </button>
          ))}
        </nav>

        {/* User Section */}
        <div style={{
          borderTop: '1px solid var(--border)', paddingTop: '16px', marginTop: '8px',
        }}>
          <div style={{
            display: 'flex', alignItems: 'center', gap: '10px',
            padding: '10px 14px', marginBottom: '8px',
            borderRadius: 'var(--radius-sm)',
            background: 'rgba(129, 140, 248, 0.04)',
            border: '1px solid var(--border)',
          }}>
            <div style={{
              width: 36, height: 36, borderRadius: 10,
              background: 'var(--gradient-primary)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontWeight: 800, fontSize: '0.85rem',
              boxShadow: '0 2px 8px rgba(129, 140, 248, 0.2)',
            }}>
              {username.charAt(0).toUpperCase()}
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: '0.85rem', fontWeight: 700 }}>{username}</div>
              <div style={{
                fontSize: '0.62rem', color: 'var(--text-muted)',
                display: 'flex', alignItems: 'center', gap: '4px',
                fontFamily: 'var(--font-mono)',
              }}>
                <Cpu size={9} /> ZK+PQC Auth
              </div>
            </div>
          </div>
          <button className="nav-item" onClick={handleLogout} style={{ color: 'var(--danger)', opacity: 0.8 }}>
            <LogOut size={16} />
            <span>Sign Out</span>
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="main-content" style={{
        opacity: pageTransition ? 0 : 1,
        transform: pageTransition ? 'translateY(6px)' : 'translateY(0)',
        transition: 'opacity 0.15s, transform 0.15s',
      }}>
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
