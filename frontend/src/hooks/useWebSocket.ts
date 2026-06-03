import { useState, useEffect, useRef, useCallback } from 'react'

export interface MitreTechnique {
  id: string
  name: string
  tactic: string
  description: string
  match_source: string
}

export interface ThreatEvent {
  pid: number
  process: string
  file: string
  threat_score: number
  threat_level: 'safe' | 'warning' | 'danger'
  timestamp: string
  type: string
  ip: string
  port: number
  // Threat Intel enrichment
  ioc_matched?: boolean
  ioc_matches?: { type: string; value: string; confidence: string }[]
  ioc_confidence?: string
  // MITRE ATT&CK enrichment
  mitre_techniques?: MitreTechnique[]
  mitre_technique_count?: number
  mitre_tactic_count?: number
  // Honeypot enrichment
  honeypot_hit?: boolean
  honeypot_alerts?: { type: string; resource: string }[]
  // UEBA enrichment
  ueba_score?: number
  ueba_user?: string
  ueba_risk_level?: string
  // GNN enrichment
  lateral_movement_detected?: boolean
  lateral_detections?: { type: string; description: string }[]
  // LLM explanation
  explanation?: string
  explanation_method?: string
  // Forensics
  forensics_capture_id?: string
  // Playbook actions
  playbook_actions?: any[]
}

interface UseWebSocketReturn {
  events: ThreatEvent[]
  isConnected: boolean
  latestScore: number
  dangerCount: number
  warningCount: number
  safeCount: number
}

export function useWebSocket(url: string): UseWebSocketReturn {
  const [events, setEvents] = useState<ThreatEvent[]>([])
  const [isConnected, setIsConnected] = useState(false)
  const ws = useRef<WebSocket | null>(null)
  const reconnectTimer = useRef<ReturnType<typeof setTimeout>>()

  const connect = useCallback(() => {
    try {
      ws.current = new WebSocket(url)

      ws.current.onopen = () => {
        setIsConnected(true)
        console.log('[AEGIS] WebSocket connected')
      }

      ws.current.onmessage = (msg) => {
        try {
          const event: ThreatEvent = JSON.parse(msg.data)
          if (event.type === 'heartbeat') return

          setEvents(prev => [event, ...prev])

          // Browser notification for danger events
          if (event.threat_level === 'danger' && Notification.permission === 'granted') {
            const extra = event.ioc_matched ? ' [IOC MATCH]' : 
                         event.honeypot_hit ? ' [HONEYPOT]' : ''
            new Notification(`⚠️ AEGIS Threat Alert${extra}`, {
              body: `Suspicious: ${event.process} (PID ${event.pid})\nScore: ${event.threat_score}/100\n${event.mitre_techniques?.[0]?.id || ''} ${event.mitre_techniques?.[0]?.name || ''}`,
              icon: '/favicon.svg',
              tag: 'aegis-threat'
            })
          }
        } catch (e) {
          console.warn('[AEGIS] Invalid message:', msg.data)
        }
      }

      ws.current.onclose = () => {
        setIsConnected(false)
        console.log('[AEGIS] WebSocket disconnected. Reconnecting...')
        reconnectTimer.current = setTimeout(connect, 3000)
      }

      ws.current.onerror = () => {
        ws.current?.close()
      }
    } catch (e) {
      console.error('[AEGIS] WebSocket error:', e)
      reconnectTimer.current = setTimeout(connect, 3000)
    }
  }, [url])

  useEffect(() => {
    // Request notification permission
    if ('Notification' in window && Notification.permission === 'default') {
      Notification.requestPermission()
    }
    connect()
    return () => {
      ws.current?.close()
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current)
    }
  }, [connect])

  const dangerCount = events.filter(e => e.threat_level === 'danger').length
  const warningCount = events.filter(e => e.threat_level === 'warning').length
  const safeCount = events.filter(e => e.threat_level === 'safe').length
  const latestScore = events[0]?.threat_score ?? 0

  return { events, isConnected, latestScore, dangerCount, warningCount, safeCount }
}
