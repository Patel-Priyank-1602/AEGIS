import { useState, useEffect } from 'react'
import {
  Activity, AlertTriangle, Shield, Wifi, WifiOff, Cpu, Eye, BarChart3,
  Globe, Hexagon, Network, Brain, TrendingUp, Zap
} from 'lucide-react'
import { useWebSocket, ThreatEvent } from '../hooks/useWebSocket'
import ThreatFeed from '../components/ThreatFeed'
import ThreatGauge from '../components/ThreatGauge'
import AlertBanner from '../components/AlertBanner'

const WS_URL = (import.meta.env.VITE_WS_URL || 'ws://localhost:8000') + '/ws/events'

function AnimatedNumber({ value, color }: { value: number; color?: string }) {
  const [display, setDisplay] = useState(0)
  useEffect(() => {
    const diff = value - display
    if (Math.abs(diff) < 1) { setDisplay(value); return }
    const timer = setTimeout(() => setDisplay(prev => prev + diff * 0.3), 30)
    return () => clearTimeout(timer)
  }, [value, display])
  return <span style={{ color }}>{Math.round(display).toLocaleString()}</span>
}

export default function Dashboard() {
  const { events, isConnected, latestScore, dangerCount, warningCount, safeCount } = useWebSocket(WS_URL)
  const [showDemo, setShowDemo] = useState(true)
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
        ioc_matched: isIOC,
        ioc_matches: isIOC ? [{ type: 'ip', value: '45.33.32.156', confidence: 'critical' }] : [],
        mitre_techniques: isDanger && mitreMap[proc] ? mitreMap[proc] :
          isWarning ? [{
            id: 'T1059.004', name: 'Unix Shell', tactic: 'Execution',
            description: 'Command interpreter', match_source: 'process'
          }] : [],
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

  const statCards = [
    { label: 'Events Processed', value: displayEvents.length, icon: BarChart3, color: 'var(--text-primary)', accent: 'rgba(129,140,248,0.08)' },
    { label: 'Safe Events', value: displaySafe, icon: Shield, color: 'var(--safe)', accent: 'rgba(6,214,160,0.08)' },
    { label: 'Warnings', value: displayWarning, icon: AlertTriangle, color: 'var(--warning)', accent: 'rgba(251,191,36,0.08)' },
    { label: 'Threats Detected', value: displayDanger, icon: Cpu, color: 'var(--danger)', accent: 'rgba(248,113,113,0.08)' },
  ]

  const enrichmentCards = [
    { label: 'IOC Matches', value: displayIOC, icon: Globe, color: '#f87171', accent: 'rgba(248,113,113,0.06)' },
    { label: 'Honeypot Hits', value: displayHoneypot, icon: Hexagon, color: '#f472b6', accent: 'rgba(244,114,182,0.06)' },
    { label: 'MITRE Tags', value: displayMitre, icon: Shield, color: '#fbbf24', accent: 'rgba(251,191,36,0.06)' },
    { label: 'AI Explanations', value: displayEvents.filter(e => e.explanation).length, icon: Brain, color: '#34d399', accent: 'rgba(52,211,153,0.06)' },
  ]

  return (
    <div className="fade-in">
      {/* Alert Banner */}
      {latestDanger && <AlertBanner event={latestDanger} />}

      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{
              width: 36, height: 36, borderRadius: 10,
              background: 'rgba(129,140,248,0.1)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <Activity size={20} color="var(--accent-indigo)" />
            </div>
            Live Monitor
          </h1>
          <p className="page-subtitle">Real-time OS event analysis with 10-layer enrichment pipeline</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{
            display: 'flex', alignItems: 'center', gap: '8px',
            padding: '8px 18px', borderRadius: '100px',
            background: 'var(--safe-bg)',
            border: '1px solid var(--safe-border)',
            fontSize: '0.78rem', fontWeight: 700,
            color: 'var(--safe)',
            backdropFilter: 'blur(8px)',
          }}>
            <div className="pulse-dot live" />
            <Wifi size={14} /> Agent Connected
          </div>
        </div>
      </div>

      {/* Stats Row */}
      <div className="grid-4" style={{ marginBottom: '12px' }}>
        {statCards.map((card, i) => (
          <div key={card.label} className="stat-card slide-in" style={{ animationDelay: `${i * 60}ms` }}>
            <div className="stat-label">
              <div style={{
                width: 22, height: 22, borderRadius: 6,
                background: card.accent,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <card.icon size={12} style={{ color: card.color }} />
              </div>
              {card.label}
            </div>
            <div className="stat-value">
              <AnimatedNumber value={card.value} color={card.color} />
            </div>
          </div>
        ))}
      </div>

      {/* Enrichment Row */}
      <div className="grid-4" style={{ marginBottom: '24px' }}>
        {enrichmentCards.map((card, i) => (
          <div key={card.label} className="stat-card slide-in" style={{ animationDelay: `${(i + 4) * 60}ms` }}>
            <div className="stat-label">
              <div style={{
                width: 22, height: 22, borderRadius: 6,
                background: card.accent,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <card.icon size={12} style={{ color: card.color }} />
              </div>
              {card.label}
            </div>
            <div className="stat-value">
              <AnimatedNumber value={card.value} color={card.color} />
            </div>
          </div>
        ))}
      </div>

      {/* Main Panels */}
      <div className="grid-2-1">
        <ThreatFeed events={displayEvents} />
        <ThreatGauge score={displayScore} dangerCount={displayDanger} totalEvents={displayEvents.length} />
      </div>
    </div>
  )
}
