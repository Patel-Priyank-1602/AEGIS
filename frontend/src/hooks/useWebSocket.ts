import { useState, useEffect, useRef, useCallback } from 'react'

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
            new Notification('⚠️ AEGIS Threat Alert', {
              body: `Suspicious: ${event.process} (PID ${event.pid})\nScore: ${event.threat_score}/100\nFile: ${event.file || 'N/A'}`,
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
