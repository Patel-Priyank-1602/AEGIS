import { useState, useEffect } from 'react'
import { Network, AlertTriangle, Globe, Server, Activity, Shield, Cpu, Lock, Fingerprint,
  Brain, Microscope, Bot, Users, Hexagon, Key, CheckCircle, Layers } from 'lucide-react'
import { api } from '../services/api'

export default function Features() {
  const [status, setStatus] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState('overview')

  useEffect(() => {
    loadStatus()
    const interval = setInterval(loadStatus, 15000)
    return () => clearInterval(interval)
  }, [])

  const loadStatus = async () => {
    try {
      const data = await api.getFeaturesStatus()
      setStatus(data)
    } catch (e) { console.error(e) }
    finally { setLoading(false) }
  }

  const features = [
    { key: 'threat_intel', name: 'Threat Intel Feeds', icon: Globe, color: '#f87171',
      desc: 'Live IOC matching from Abuse.ch, URLhaus, SSL Blacklist',
      stat: (s: any) => `${s?.total_iocs?.toLocaleString() || 0} IOCs loaded` },
    { key: 'mitre_attack', name: 'MITRE ATT&CK Tagging', icon: Shield, color: '#fbbf24',
      desc: 'Automatic technique ID tagging on every event',
      stat: (s: any) => `${s?.techniques_loaded || 0} tactics covered` },
    { key: 'playbooks', name: 'Automated Playbooks', icon: Cpu, color: '#a78bfa',
      desc: 'Idempotent, reversible response actions',
      stat: (s: any) => `${s?.total_executions || 0} executions` },
    { key: 'honeypot', name: 'Honeypot Deception', icon: Hexagon, color: '#f472b6',
      desc: 'Zero false-positive canary resources',
      stat: (s: any) => `${s?.total_hits || 0} intrusions caught` },
    { key: 'forensics', name: 'Memory Forensics', icon: Microscope, color: '#22d3ee',
      desc: 'Process memory capture + YARA scanning',
      stat: (s: any) => `${s?.total_captures || 0} captures, ${s?.total_yara_matches || 0} YARA hits` },
    { key: 'llm_explainer', name: 'LLM Alert Explainer', icon: Bot, color: '#34d399',
      desc: 'Plain-English kill chain explanations via RAG over MITRE ATT&CK',
      stat: (s: any) => `${s?.explanations_generated || 0} explanations (${s?.method || 'template'})` },
    { key: 'ueba', name: 'UEBA Baselines', icon: Users, color: '#818cf8',
      desc: 'Per-user behavioral profiling for insider threat detection',
      stat: (s: any) => `${s?.total_users || 0} users, ${s?.risky_users || 0} risky` },
    { key: 'gnn_graph', name: 'GNN Lateral Movement', icon: Network, color: '#fb923c',
      desc: 'Network graph analysis for multi-hop attack detection',
      stat: (s: any) => `${s?.total_nodes || 0} nodes, ${s?.total_edges || 0} edges` },
    { key: 'federated', name: 'Federated Learning', icon: Brain, color: '#2dd4bf',
      desc: 'Privacy-preserving distributed model training (DP ε=0.1)',
      stat: (s: any) => `Round ${s?.global_round || 0}, ${s?.registered_clients || 0} clients` },
    { key: 'pqc', name: 'Post-Quantum Crypto', icon: Key, color: '#c084fc',
      desc: 'Dilithium signatures + Kyber key exchange (NIST PQC)',
      stat: (s: any) => `${s?.signatures_created || 0} signatures (${s?.dilithium_algorithm || 'N/A'})` },
  ]

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
              <Layers size={20} color="var(--accent-indigo)" />
            </div>
            Advanced Features
          </h1>
          <p className="page-subtitle">Status dashboard for all 10 security capabilities</p>
        </div>
        <div style={{
          padding: '8px 18px', borderRadius: '100px', fontSize: '0.75rem', fontWeight: 800,
          background: status ? 'linear-gradient(135deg, rgba(6,214,160,0.1), rgba(129,140,248,0.1))' : 'rgba(248, 113, 113, 0.1)',
          border: status ? '1px solid rgba(6,214,160,0.2)' : '1px solid rgba(248, 113, 113, 0.2)', 
          color: status ? 'var(--safe)' : 'var(--danger)',
          display: 'flex', alignItems: 'center', gap: '6px',
          backdropFilter: 'blur(8px)',
        }}>
          {status ? <CheckCircle size={14} /> : <AlertTriangle size={14} />}
          {loading ? '...' : (status ? '10/10 Features Active' : 'Offline - Backend Unreachable')}
        </div>
      </div>

      {/* Feature Grid */}
      <div style={{
        display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))',
        gap: '16px',
      }}>
        {features.map((f, i) => {
          const featureStatus = status?.[f.key]
          const Icon = f.icon
          return (
            <div key={f.key} className="card slide-in" style={{
              padding: '22px', cursor: 'default',
              animationDelay: `${i * 50}ms`,
              borderLeft: 'none',
            }}>
              {/* Color accent bar */}
              <div style={{
                position: 'absolute', top: 0, left: 0,
                width: '3px', height: '100%',
                background: `linear-gradient(180deg, ${f.color}, transparent)`,
                borderRadius: '0 0 0 var(--radius-lg)',
              }} />

              <div style={{ display: 'flex', alignItems: 'center', gap: '14px', marginBottom: '12px' }}>
                <div style={{
                  width: 40, height: 40, borderRadius: 12,
                  background: `${f.color}12`, display: 'flex', alignItems: 'center',
                  justifyContent: 'center', color: f.color,
                  border: `1px solid ${f.color}20`,
                  transition: 'all 0.3s',
                }}>
                  <Icon size={18} />
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontWeight: 700, fontSize: '0.9rem' }}>{f.name}</div>
                  <div style={{
                    fontSize: '0.62rem', fontWeight: 700, color: status ? 'var(--safe)' : 'var(--danger)',
                    display: 'flex', alignItems: 'center', gap: '4px',
                    textTransform: 'uppercase', letterSpacing: '0.08em',
                  }}>
                    <div style={{
                      width: 6, height: 6, borderRadius: '50%', background: status ? 'var(--safe)' : 'var(--danger)',
                      boxShadow: status ? '0 0 6px rgba(6,214,160,0.4)' : '0 0 6px rgba(248,113,113,0.4)',
                    }} />
                    {status ? 'Active' : 'Offline'}
                  </div>
                </div>
              </div>

              <p style={{
                fontSize: '0.76rem', color: 'var(--text-muted)', marginBottom: '14px',
                lineHeight: 1.6,
              }}>
                {f.desc}
              </p>

              <div style={{
                fontSize: '0.7rem', fontFamily: 'var(--font-mono)', fontWeight: 600,
                color: status ? 'var(--accent)' : 'var(--text-muted)',
                padding: '8px 12px', borderRadius: 'var(--radius-sm)',
                background: status ? 'rgba(6,214,160,0.04)' : 'rgba(255,255,255,0.03)',
                border: status ? '1px solid rgba(6,214,160,0.08)' : '1px solid rgba(255,255,255,0.05)',
              }}>
                {status ? f.stat(featureStatus) : 'Service Unavailable'}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
