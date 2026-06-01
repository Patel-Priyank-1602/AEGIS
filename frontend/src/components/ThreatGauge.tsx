import { useEffect, useRef } from 'react'

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
      // Smooth animation toward target score
      animatedScore.current += (score - animatedScore.current) * 0.08
      const currentScore = animatedScore.current

      ctx.clearRect(0, 0, size, size)

      // Background arc
      ctx.beginPath()
      ctx.arc(cx, cy, radius, startAngle, endAngle)
      ctx.strokeStyle = 'rgba(99, 102, 241, 0.08)'
      ctx.lineWidth = lineWidth
      ctx.lineCap = 'round'
      ctx.stroke()

      // Score arc
      const scoreAngle = startAngle + (currentScore / 100) * totalAngle
      const gradient = ctx.createLinearGradient(0, 0, size, size)
      if (currentScore > 70) {
        gradient.addColorStop(0, '#ef4444')
        gradient.addColorStop(1, '#f97316')
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
      if (currentScore > 70) {
        ctx.beginPath()
        ctx.arc(cx, cy, radius, startAngle, scoreAngle)
        ctx.strokeStyle = 'rgba(239, 68, 68, 0.15)'
        ctx.lineWidth = lineWidth + 12
        ctx.lineCap = 'round'
        ctx.stroke()
      }

      // Center score text
      ctx.textAlign = 'center'
      ctx.textBaseline = 'middle'

      ctx.font = '700 42px "JetBrains Mono", monospace'
      ctx.fillStyle = currentScore > 70 ? '#ef4444' : currentScore > 30 ? '#fbbf24' : '#06d6a0'
      ctx.fillText(Math.round(currentScore).toString(), cx, cy - 8)

      ctx.font = '500 11px Inter, sans-serif'
      ctx.fillStyle = '#4a5578'
      ctx.fillText('THREAT SCORE', cx, cy + 22)

      // Tick marks
      for (let i = 0; i <= 10; i++) {
        const angle = startAngle + (i / 10) * totalAngle
        const innerR = radius + 16
        const outerR = radius + (i % 5 === 0 ? 24 : 20)
        const x1 = cx + Math.cos(angle) * innerR
        const y1 = cy + Math.sin(angle) * innerR
        const x2 = cx + Math.cos(angle) * outerR
        const y2 = cy + Math.sin(angle) * outerR

        ctx.beginPath()
        ctx.moveTo(x1, y1)
        ctx.lineTo(x2, y2)
        ctx.strokeStyle = 'rgba(99, 102, 241, 0.15)'
        ctx.lineWidth = i % 5 === 0 ? 2 : 1
        ctx.stroke()
      }

      frame = requestAnimationFrame(animate)
    }

    animate()
    return () => cancelAnimationFrame(frame)
  }, [score])

  return (
    <div className="card" style={{ height: '480px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
      <h2 style={{
        fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase',
        letterSpacing: '0.08em', color: 'var(--text-muted)',
        marginBottom: '16px', alignSelf: 'flex-start',
      }}>
        Threat Level
      </h2>

      {/* Gauge */}
      <div className={score > 70 ? 'danger-glow' : ''} style={{ borderRadius: '50%', marginBottom: '24px' }}>
        <canvas ref={canvasRef} />
      </div>

      {/* Status text */}
      <div style={{
        textAlign: 'center', marginBottom: '24px',
        fontSize: '0.85rem', fontWeight: 600,
        color: score > 70 ? 'var(--danger)' : score > 30 ? 'var(--warning)' : 'var(--safe)',
      }}>
        {score > 85 ? '⚠ CRITICAL THREAT DETECTED' :
         score > 70 ? '⚠ Danger — Suspicious Activity' :
         score > 30 ? 'Warning — Unusual Behavior' :
         '✓ System Normal'}
      </div>

      {/* Mini stats */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', width: '100%' }}>
        <div style={{
          padding: '12px', borderRadius: 'var(--radius-sm)',
          background: 'var(--danger-bg)', border: '1px solid var(--danger-border)',
          textAlign: 'center',
        }}>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--danger)' }}>
            {dangerCount}
          </div>
          <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Critical Alerts
          </div>
        </div>
        <div style={{
          padding: '12px', borderRadius: 'var(--radius-sm)',
          background: 'var(--safe-bg)', border: '1px solid var(--safe-border)',
          textAlign: 'center',
        }}>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--safe)' }}>
            {totalEvents}
          </div>
          <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Total Events
          </div>
        </div>
      </div>
    </div>
  )
}
