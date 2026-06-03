import { useState, useEffect } from 'react'
import { Activity, AlertTriangle, Shield, Wifi, WifiOff, Cpu, Eye, BarChart3 } from 'lucide-react'
import { useWebSocket, ThreatEvent } from '../hooks/useWebSocket'
import ThreatFeed from '../components/ThreatFeed'
import ThreatGauge from '../components/ThreatGauge'
import AlertBanner from '../components/AlertBanner'

const WS_URL = (import.meta.env.VITE_WS_URL || 'ws://localhost:8000') + '/ws/events'

export default function Dashboard() {
  const { events, isConnected, latestScore, dangerCount, warningCount, safeCount } = useWebSocket(WS_URL)
  const [showDemo, setShowDemo] = useState(false)
  const [demoEvents, setDemoEvents] = useState<ThreatEvent[]>([])

  // Demo mode: simulate events when no agent is connected
  useEffect(() => {
    if (isConnected || !showDemo) return

    const processes = ['code', 'python3', 'node', 'git', 'chrome', 'docker', 'npm', 'systemd']
    const files = ['/home/user/project/app.py', '/tmp/build.log', '/home/user/.config/settings.json', '/var/log/syslog']
    const badProcesses = ['nc', 'nmap', 'bash']
    const badFiles = ['/etc/shadow', '/root/.ssh/id_rsa']

    const interval = setInterval(() => {
      const isDanger = Math.random() < 0.08
      const isWarning = !isDanger && Math.random() < 0.15

      const event: ThreatEvent = {
        pid: Math.floor(Math.random() * 9000) + 1000,
        process: isDanger ? badProcesses[Math.floor(Math.random() * badProcesses.length)]
          : processes[Math.floor(Math.random() * processes.length)],
        file: isDanger ? badFiles[Math.floor(Math.random() * badFiles.length)]
          : files[Math.floor(Math.random() * files.length)],
        threat_score: isDanger ? 75 + Math.random() * 25
          : isWarning ? 35 + Math.random() * 30
            : Math.random() * 25,
        threat_level: isDanger ? 'danger' : isWarning ? 'warning' : 'safe',
        timestamp: new Date().toISOString(),
        type: Math.random() > 0.3 ? 'file_open' : 'process_exec',
        ip: isDanger ? '45.33.32.156' : '127.0.0.1',
        port: isDanger ? 4444 : 0,
      }

      setDemoEvents(prev => [event, ...prev].slice(0, 200))
    }, 800)

    return () => clearInterval(interval)
  }, [isConnected, showDemo])

  const displayEvents = isConnected ? events : demoEvents
  const displayScore = displayEvents[0]?.threat_score ?? 0
  const displayDanger = displayEvents.filter(e => e.threat_level === 'danger').length
  const displayWarning = displayEvents.filter(e => e.threat_level === 'warning').length
  const displaySafe = displayEvents.filter(e => e.threat_level === 'safe').length
  const latestDanger = displayEvents.find(e => e.threat_level === 'danger')

  return (
    <div className="fade-in">
      {/* Alert Banner */}
      {latestDanger && <AlertBanner event={latestDanger} />}

      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <Activity size={24} />
            Live Monitor
          </h1>
          <p className="page-subtitle">Real-time OS event analysis and threat detection</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          {!isConnected && (
            <button
              className="btn btn-ghost"
              onClick={() => setShowDemo(!showDemo)}
              style={{ fontSize: '0.8rem' }}
            >
              <Eye size={14} />
              {showDemo ? 'Stop Demo' : 'Demo Mode'}
            </button>
          )}
          <div style={{
            display: 'flex', alignItems: 'center', gap: '8px',
            padding: '8px 16px', borderRadius: '100px',
            background: isConnected ? 'var(--safe-bg)' : 'var(--danger-bg)',
            border: `1px solid ${isConnected ? 'var(--safe-border)' : 'var(--danger-border)'}`,
            fontSize: '0.8rem', fontWeight: 600,
            color: isConnected ? 'var(--safe)' : 'var(--danger)',
          }}>
            <div className={`pulse-dot ${isConnected ? 'live' : 'offline'}`} />
            {isConnected ? (
              <><Wifi size={14} /> Agent Connected</>
            ) : (
              <><WifiOff size={14} /> {showDemo ? 'Demo Mode' : 'Agent Offline'}</>
            )}
          </div>
        </div>
      </div>

      {/* Stats Row */}
      <div className="grid-4" style={{ marginBottom: '24px' }}>
        <div className="stat-card">
          <div className="stat-label">
            <BarChart3 size={12} style={{ marginRight: '4px', verticalAlign: 'middle' }} />
            Events Processed
          </div>
          <div className="stat-value" style={{ color: 'var(--text-primary)' }}>
            {displayEvents.length.toLocaleString()}
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-label">
            <Shield size={12} style={{ marginRight: '4px', verticalAlign: 'middle' }} />
            Safe Events
          </div>
          <div className="stat-value safe">{displaySafe}</div>
        </div>

        <div className="stat-card">
          <div className="stat-label">
            <AlertTriangle size={12} style={{ marginRight: '4px', verticalAlign: 'middle' }} />
            Warnings
          </div>
          <div className="stat-value warning">{displayWarning}</div>
        </div>

        <div className="stat-card">
          <div className="stat-label">
            <Cpu size={12} style={{ marginRight: '4px', verticalAlign: 'middle' }} />
            Threats Detected
          </div>
          <div className="stat-value danger">{displayDanger}</div>
        </div>
      </div>

      {/* Main Panels */}
      <div className="grid-2-1">
        <ThreatFeed events={displayEvents} />
        <ThreatGauge score={displayScore} dangerCount={displayDanger} totalEvents={displayEvents.length} />
      </div>
    </div>
  )
}
