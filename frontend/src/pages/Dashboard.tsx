import { useState, useEffect } from 'react'
import { Activity, AlertTriangle, Shield, Wifi, WifiOff, Cpu, Eye, BarChart3,
  Globe, Hexagon, Network, Brain } from 'lucide-react'
import { useWebSocket, ThreatEvent } from '../hooks/useWebSocket'
import ThreatFeed from '../components/ThreatFeed'
import ThreatGauge from '../components/ThreatGauge'
import AlertBanner from '../components/AlertBanner'

const WS_URL = (import.meta.env.VITE_WS_URL || 'ws://localhost:8000') + '/ws/events'

export default function Dashboard() {
  const { events, isConnected, latestScore, dangerCount, warningCount, safeCount } = useWebSocket(WS_URL)
  const [showDemo, setShowDemo] = useState(false)
  const [demoEvents, setDemoEvents] = useState<ThreatEvent[]>([])

  // Demo mode: simulate enriched events when no agent is connected
  useEffect(() => {
    if (isConnected || !showDemo) return

    const processes = ['code', 'python3', 'node', 'git', 'chrome', 'docker', 'npm', 'systemd']
    const files = ['/home/user/project/app.py', '/tmp/build.log', '/home/user/.config/settings.json', '/var/log/syslog']
    const badProcesses = ['nc', 'nmap', 'bash', 'hydra']
    const badFiles = ['/etc/shadow', '/root/.ssh/id_rsa', '/root/.aws/credentials']

    const mitreMap: Record<string, any[]> = {
      nc: [{ id: 'T1095', name: 'Non-Application Layer Protocol', tactic: 'Command and Control', description: 'C2 over raw sockets' }],
      nmap: [{ id: 'T1046', name: 'Network Service Discovery', tactic: 'Discovery', description: 'Port scanning' }],
      hydra: [{ id: 'T1110', name: 'Brute Force', tactic: 'Credential Access', description: 'Password guessing' }],
    }

    const interval = setInterval(() => {
      const isDanger = Math.random() < 0.08
      const isWarning = !isDanger && Math.random() < 0.15
      const isIOC = isDanger && Math.random() < 0.5
      const isHoneypot = isDanger && Math.random() < 0.2
      const proc = isDanger ? badProcesses[Math.floor(Math.random() * badProcesses.length)]
        : processes[Math.floor(Math.random() * processes.length)]

      const event: ThreatEvent = {
        pid: Math.floor(Math.random() * 9000) + 1000,
        process: proc,
        file: isDanger ? badFiles[Math.floor(Math.random() * badFiles.length)]
          : files[Math.floor(Math.random() * files.length)],
        threat_score: isDanger ? 75 + Math.random() * 25
          : isWarning ? 35 + Math.random() * 30 : Math.random() * 25,
        threat_level: isDanger ? 'danger' : isWarning ? 'warning' : 'safe',
        timestamp: new Date().toISOString(),
        type: Math.random() > 0.3 ? 'file_open' : 'process_exec',
        ip: isDanger ? '45.33.32.156' : '127.0.0.1',
        port: isDanger ? 4444 : 0,
        // Enrichment fields
        ioc_matched: isIOC,
        ioc_matches: isIOC ? [{ type: 'ip', value: '45.33.32.156', confidence: 'critical' }] : [],
        mitre_techniques: isDanger && mitreMap[proc] ? mitreMap[proc] :
          isWarning ? [{ id: 'T1059.004', name: 'Unix Shell', tactic: 'Execution',
            description: 'Command interpreter', match_source: 'process' }] : [],
        mitre_technique_count: isDanger ? 2 : isWarning ? 1 : 0,
        honeypot_hit: isHoneypot,
        ueba_score: isDanger ? 60 + Math.random() * 30 : Math.random() * 20,
        ueba_risk_level: isDanger ? 'high' : 'low',
        explanation: isDanger ? `Process '${proc}' connected to known C2 IP 45.33.32.156 on port 4444. This matches MITRE ATT&CK T1095 (Non-Application Layer Protocol). Immediate action: terminate the process and block the IP.` : undefined,
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
  const displayIOC = displayEvents.filter(e => e.ioc_matched).length
  const displayHoneypot = displayEvents.filter(e => e.honeypot_hit).length
  const displayMitre = displayEvents.reduce((sum, e) => sum + (e.mitre_technique_count || 0), 0)
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
          <p className="page-subtitle">Real-time OS event analysis with 10-layer enrichment pipeline</p>
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

      {/* Stats Row - Original 4 */}
      <div className="grid-4" style={{ marginBottom: '12px' }}>
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

      {/* Stats Row - Enrichment */}
      <div className="grid-4" style={{ marginBottom: '24px' }}>
        <div className="stat-card">
          <div className="stat-label">
            <Globe size={12} style={{ marginRight: '4px', verticalAlign: 'middle' }} />
            IOC Matches
          </div>
          <div className="stat-value" style={{ color: '#ef4444' }}>{displayIOC}</div>
        </div>

        <div className="stat-card">
          <div className="stat-label">
            <Hexagon size={12} style={{ marginRight: '4px', verticalAlign: 'middle' }} />
            Honeypot Hits
          </div>
          <div className="stat-value" style={{ color: '#ec4899' }}>{displayHoneypot}</div>
        </div>

        <div className="stat-card">
          <div className="stat-label">
            <Shield size={12} style={{ marginRight: '4px', verticalAlign: 'middle' }} />
            MITRE Tags
          </div>
          <div className="stat-value" style={{ color: '#f59e0b' }}>{displayMitre}</div>
        </div>

        <div className="stat-card">
          <div className="stat-label">
            <Brain size={12} style={{ marginRight: '4px', verticalAlign: 'middle' }} />
            AI Explanations
          </div>
          <div className="stat-value" style={{ color: '#10b981' }}>
            {displayEvents.filter(e => e.explanation).length}
          </div>
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
