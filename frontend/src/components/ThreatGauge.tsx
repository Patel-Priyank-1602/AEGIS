import { useEffect, useRef } from 'react'
import { Shield, AlertTriangle, Activity } from 'lucide-react'

interface Props {
  score: number
  dangerCount: number
  totalEvents: number
}

export default function ThreatGauge({ score, dangerCount, totalEvents }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const animatedScore = useRef(0)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const size = 220
    canvas.width = size * 2
    canvas.height = size * 2
    canvas.style.width = `${size}px`
    canvas.style.height = `${size}px`
    ctx.scale(2, 2) // Retina

    const cx = size / 2
    const cy = size / 2
    const radius = 85
    const lineWidth = 10
    const startAngle = Math.PI * 0.75
    const endAngle = Math.PI * 2.25
    const totalAngle = endAngle - startAngle

    let frame: number

    const animate = () => {
      animatedScore.current += (score - animatedScore.current) * 0.06
      const currentScore = animatedScore.current

      ctx.clearRect(0, 0, size, size)

      // Background arc with segments
      for (let i = 0; i < 50; i++) {
        const segStart = startAngle + (i / 50) * totalAngle
        const segEnd = startAngle + ((i + 0.7) / 50) * totalAngle
        ctx.beginPath()
        ctx.arc(cx, cy, radius, segStart, segEnd)
        ctx.strokeStyle = 'rgba(129, 140, 248, 0.06)'
        ctx.lineWidth = lineWidth
        ctx.lineCap = 'round'
        ctx.stroke()
      }

      // Score arc
      const scoreAngle = startAngle + (currentScore / 100) * totalAngle
      const gradient = ctx.createLinearGradient(0, 0, size, size)
      if (currentScore > 70) {
        gradient.addColorStop(0, '#f87171')
        gradient.addColorStop(1, '#fb923c')
      } else if (currentScore > 30) {
        gradient.addColorStop(0, '#fbbf24')
        gradient.addColorStop(1, '#f59e0b')
      } else {
        gradient.addColorStop(0, '#06d6a0')
        gradient.addColorStop(1, '#34d399')
      }

      ctx.beginPath()
      ctx.arc(cx, cy, radius, startAngle, scoreAngle)
      ctx.strokeStyle = gradient
      ctx.lineWidth = lineWidth
      ctx.lineCap = 'round'
      ctx.stroke()

      // Glow effect
      if (currentScore > 50) {
        ctx.beginPath()
        ctx.arc(cx, cy, radius, startAngle, scoreAngle)
        const glowColor = currentScore > 70 ? 'rgba(248, 113, 113, 0.12)' : 'rgba(251, 191, 36, 0.08)'
        ctx.strokeStyle = glowColor
        ctx.lineWidth = lineWidth + 16
        ctx.lineCap = 'round'
        ctx.stroke()
      }

      // Inner circle decoration
      ctx.beginPath()
      ctx.arc(cx, cy, radius - 22, 0, Math.PI * 2)
      ctx.strokeStyle = 'rgba(129, 140, 248, 0.04)'
      ctx.lineWidth = 1
      ctx.stroke()

      // Center score text
      ctx.textAlign = 'center'
      ctx.textBaseline = 'middle'

      ctx.font = '800 44px "JetBrains Mono", monospace'
      ctx.fillStyle = currentScore > 70 ? '#f87171' : currentScore > 30 ? '#fbbf24' : '#06d6a0'
      ctx.fillText(Math.round(currentScore).toString(), cx, cy - 8)

      ctx.font = '600 10px "Outfit", sans-serif'
      ctx.fillStyle = '#4d5775'
      ctx.letterSpacing = '2px'
      ctx.fillText('THREAT SCORE', cx, cy + 24)

      // Tick marks
      for (let i = 0; i <= 10; i++) {
        const angle = startAngle + (i / 10) * totalAngle
        const innerR = radius + 16
        const outerR = radius + (i % 5 === 0 ? 26 : 20)
        const x1 = cx + Math.cos(angle) * innerR
        const y1 = cy + Math.sin(angle) * innerR
        const x2 = cx + Math.cos(angle) * outerR
        const y2 = cy + Math.sin(angle) * outerR

        ctx.beginPath()
        ctx.moveTo(x1, y1)
        ctx.lineTo(x2, y2)
        ctx.strokeStyle = 'rgba(129, 140, 248, 0.12)'
        ctx.lineWidth = i % 5 === 0 ? 2 : 1
        ctx.stroke()
      }

      frame = requestAnimationFrame(animate)
    }

    animate()
    return () => cancelAnimationFrame(frame)
  }, [score])

  const statusText = score > 85 ? 'CRITICAL THREAT'
    : score > 70 ? 'Danger Level'
    : score > 30 ? 'Warning Level'
    : 'System Normal'

  const statusColor = score > 70 ? 'var(--danger)' : score > 30 ? 'var(--warning)' : 'var(--safe)'

  return (
    <div className="card" style={{
      height: '480px', display: 'flex', flexDirection: 'column',
      alignItems: 'center', justifyContent: 'center',
    }}>
      <h2 style={{
        fontSize: '0.72rem', fontWeight: 700, textTransform: 'uppercase',
        letterSpacing: '0.1em', color: 'var(--text-muted)',
        marginBottom: '16px', alignSelf: 'flex-start',
        display: 'flex', alignItems: 'center', gap: '8px',
      }}>
        <div style={{
          width: 24, height: 24, borderRadius: 6,
          background: 'rgba(129,140,248,0.08)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <Shield size={12} color="var(--accent-indigo)" />
        </div>
        Threat Level
      </h2>

      {/* Gauge */}
      <div className={score > 70 ? 'danger-glow' : ''} style={{
        borderRadius: '50%', marginBottom: '20px',
        padding: '4px',
      }}>
        <canvas ref={canvasRef} />
      </div>

      {/* Status text */}
      <div style={{
        textAlign: 'center', marginBottom: '24px',
        padding: '6px 20px', borderRadius: '100px',
        background: score > 70 ? 'var(--danger-bg)' : score > 30 ? 'var(--warning-bg)' : 'var(--safe-bg)',
        border: `1px solid ${score > 70 ? 'var(--danger-border)' : score > 30 ? 'var(--warning-border)' : 'var(--safe-border)'}`,
        fontSize: '0.78rem', fontWeight: 700,
        color: statusColor,
        display: 'flex', alignItems: 'center', gap: '6px',
      }}>
        {score > 70 ? <AlertTriangle size={13} /> : score > 30 ? <Activity size={13} /> : <Shield size={13} />}
        {statusText}
      </div>

      {/* Mini stats */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', width: '100%' }}>
        <div style={{
          padding: '14px', borderRadius: 'var(--radius-sm)',
          background: 'var(--danger-bg)', border: '1px solid var(--danger-border)',
          textAlign: 'center',
        }}>
          <div style={{
            fontSize: '1.6rem', fontWeight: 800, fontFamily: 'var(--font-mono)',
            color: 'var(--danger)', textShadow: '0 0 16px rgba(248,113,113,0.15)',
          }}>
            {dangerCount}
          </div>
          <div style={{
            fontSize: '0.62rem', color: 'var(--text-muted)',
            textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 600,
          }}>
            Critical Alerts
          </div>
        </div>
        <div style={{
          padding: '14px', borderRadius: 'var(--radius-sm)',
          background: 'var(--safe-bg)', border: '1px solid var(--safe-border)',
          textAlign: 'center',
        }}>
          <div style={{
            fontSize: '1.6rem', fontWeight: 800, fontFamily: 'var(--font-mono)',
            color: 'var(--safe)', textShadow: '0 0 16px rgba(6,214,160,0.15)',
          }}>
            {totalEvents}
          </div>
          <div style={{
            fontSize: '0.62rem', color: 'var(--text-muted)',
            textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 600,
          }}>
            Total Events
          </div>
        </div>
      </div>
    </div>
  )
}
