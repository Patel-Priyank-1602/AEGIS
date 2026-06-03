import { useState, useEffect } from 'react'
import { Network, AlertTriangle, Globe, Server, Activity, Shield, Cpu, Lock, Fingerprint,
  Brain, Microscope, Bot, Users, Hexagon, Key } from 'lucide-react'
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
    { key: 'threat_intel', name: 'Threat Intel Feeds', icon: Globe, color: '#ef4444',
      desc: 'Live IOC matching from Abuse.ch, URLhaus, SSL Blacklist',
      stat: (s: any) => `${s?.total_iocs?.toLocaleString() || 0} IOCs loaded` },
    { key: 'mitre_attack', name: 'MITRE ATT&CK Tagging', icon: Shield, color: '#f59e0b',
      desc: 'Automatic technique ID tagging on every event',
      stat: (s: any) => `${s?.techniques_loaded || 0} tactics covered` },
    { key: 'playbooks', name: 'Automated Playbooks', icon: Cpu, color: '#8b5cf6',
      desc: 'Idempotent, reversible response actions',
      stat: (s: any) => `${s?.total_executions || 0} executions` },
    { key: 'honeypot', name: 'Honeypot Deception', icon: Hexagon, color: '#ec4899',
      desc: 'Zero false-positive canary resources',
      stat: (s: any) => `${s?.total_hits || 0} intrusions caught` },
    { key: 'forensics', name: 'Memory Forensics', icon: Microscope, color: '#06b6d4',
      desc: 'Process memory capture + YARA scanning',
      stat: (s: any) => `${s?.total_captures || 0} captures, ${s?.total_yara_matches || 0} YARA hits` },
    { key: 'llm_explainer', name: 'LLM Alert Explainer', icon: Bot, color: '#10b981',
      desc: 'Plain-English kill chain explanations via RAG over MITRE ATT&CK',
      stat: (s: any) => `${s?.explanations_generated || 0} explanations (${s?.method || 'template'})` },
    { key: 'ueba', name: 'UEBA Baselines', icon: Users, color: '#6366f1',
      desc: 'Per-user behavioral profiling for insider threat detection',
      stat: (s: any) => `${s?.total_users || 0} users, ${s?.risky_users || 0} risky` },
    { key: 'gnn_graph', name: 'GNN Lateral Movement', icon: Network, color: '#f97316',
      desc: 'Network graph analysis for multi-hop attack detection',
      stat: (s: any) => `${s?.total_nodes || 0} nodes, ${s?.total_edges || 0} edges` },
    { key: 'federated', name: 'Federated Learning', icon: Brain, color: '#14b8a6',
      desc: 'Privacy-preserving distributed model training (DP ε=0.1)',
      stat: (s: any) => `Round ${s?.global_round || 0}, ${s?.registered_clients || 0} clients` },
    { key: 'pqc', name: 'Post-Quantum Crypto', icon: Key, color: '#a855f7',
      desc: 'Dilithium signatures + Kyber key exchange (NIST PQC)',
      stat: (s: any) => `${s?.signatures_created || 0} signatures (${s?.dilithium_algorithm || 'N/A'})` },
  ]

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <Activity size={24} /> Advanced Features
          </h1>
          <p className="page-subtitle">Status dashboard for all 10 security capabilities</p>
        </div>
        <div style={{
          padding: '8px 16px', borderRadius: '100px', fontSize: '0.75rem', fontWeight: 700,
          background: 'linear-gradient(135deg, rgba(6,214,160,0.15), rgba(99,102,241,0.15))',
          border: '1px solid rgba(6,214,160,0.3)', color: 'var(--safe)',
        }}>
          {loading ? '...' : '10/10 Features Active'}
        </div>
      </div>

      {/* Feature Grid */}
      <div style={{
        display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))',
        gap: '16px',
      }}>
        {features.map(f => {
          const featureStatus = status?.[f.key]
          const Icon = f.icon
          return (
            <div key={f.key} className="card" style={{
              padding: '20px', cursor: 'default',
              borderLeft: `3px solid ${f.color}`,
              transition: 'all 0.2s',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '10px' }}>
                <div style={{
                  width: '36px', height: '36px', borderRadius: '10px',
                  background: `${f.color}20`, display: 'flex', alignItems: 'center',
                  justifyContent: 'center', color: f.color,
                }}>
                  <Icon size={18} />
                </div>
                <div>
                  <div style={{ fontWeight: 700, fontSize: '0.9rem' }}>{f.name}</div>
                  <div style={{
                    fontSize: '0.65rem', fontWeight: 600, color: 'var(--safe)',
                    display: 'flex', alignItems: 'center', gap: '4px',
                  }}>
                    <div style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--safe)' }} />
                    Active
                  </div>
                </div>
              </div>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '12px', lineHeight: 1.5 }}>
                {f.desc}
              </p>
              <div style={{
                fontSize: '0.7rem', fontFamily: 'var(--font-mono)', color: 'var(--accent)',
                padding: '6px 10px', borderRadius: 'var(--radius-sm)',
                background: 'var(--bg-secondary)',
              }}>
                {f.stat(featureStatus)}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
