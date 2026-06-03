const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

async function request(path: string, options?: RequestInit) {
  const token = localStorage.getItem('aegis_token')
  const res = await fetch(`${API_URL}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options?.headers,
    },
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Request failed' }))
    throw new Error(err.detail || `HTTP ${res.status}`)
  }
  return res.json()
}

export const api = {
  // Health
  health: () => request('/health'),

  // Events
  getRecentEvents: (limit = 100) => request(`/api/events/recent?limit=${limit}`),
  getEventStats: () => request('/api/events/stats'),
  getModelStatus: () => request('/api/events/model-status'),

  // Audit
  getAuditLogs: (limit = 50, decrypt = false) =>
    request(`/api/audit?limit=${limit}&decrypt=${decrypt}`),
  verifyChain: () => request('/api/audit/verify/chain'),
  exportAudit: () => request('/api/audit/export/json?decrypt=true'),
  clearAuditLogs: () => request('/api/audit/clear', { method: 'DELETE' }),

  // Auth
  verifySession: (token: string) => request(`/api/auth/verify-session?token=${token}`),

  // ─── Advanced Features ───────────────────────────────────────
  // Unified status
  getFeaturesStatus: () => request('/api/features/status'),

  // Threat Intel
  getThreatIntelStats: () => request('/api/threat-intel/stats'),
  refreshThreatFeeds: () => request('/api/threat-intel/refresh', { method: 'POST' }),
  addCustomIOC: (data: { ioc_type: string; value: string; critical?: boolean }) =>
    request('/api/threat-intel/add-ioc', { method: 'POST', body: JSON.stringify(data) }),
  checkIP: (ip: string) => request(`/api/threat-intel/check/${ip}`),

  // MITRE ATT&CK
  getMitreCoverage: () => request('/api/mitre/coverage'),
  getMitreTechnique: (id: string) => request(`/api/mitre/technique/${id}`),

  // Playbooks
  getPlaybooks: () => request('/api/playbooks'),
  getPlaybookExecutions: (limit = 50) => request(`/api/playbooks/executions?limit=${limit}`),
  undoAction: (actionId: string) => request(`/api/playbooks/undo/${actionId}`, { method: 'POST' }),
  togglePlaybooks: (enabled: boolean) =>
    request(`/api/playbooks/toggle?enabled=${enabled}`, { method: 'POST' }),

  // Honeypot
  getHoneypotStats: () => request('/api/honeypot/stats'),
  getHoneypotAlerts: (limit = 50) => request(`/api/honeypot/alerts?limit=${limit}`),
  getHoneypotResources: () => request('/api/honeypot/resources'),

  // Forensics
  getForensicsStats: () => request('/api/forensics/stats'),
  getForensicsCaptures: (limit = 20) => request(`/api/forensics/captures?limit=${limit}`),
  getCapture: (id: string) => request(`/api/forensics/capture/${id}`),

  // LLM Explainer
  getExplainerStats: () => request('/api/explainer/stats'),
  explainAlert: (event: any) =>
    request('/api/explain', { method: 'POST', body: JSON.stringify(event) }),

  // UEBA
  getUEBAStats: () => request('/api/ueba/stats'),
  getUEBAProfiles: () => request('/api/ueba/profiles'),
  getUEBAProfile: (userId: string) => request(`/api/ueba/profile/${userId}`),
  getRiskyUsers: (minScore = 30) => request(`/api/ueba/risky-users?min_score=${minScore}`),

  // GNN / Network Graph
  getGraphSnapshot: () => request('/api/graph/snapshot'),
  getGraphStats: () => request('/api/graph/stats'),
  getGraphAlerts: (limit = 50) => request(`/api/graph/alerts?limit=${limit}`),

  // Federated Learning
  getFederatedStats: () => request('/api/federated/stats'),
  getFederatedModel: () => request('/api/federated/model'),

  // Post-Quantum Crypto
  getPQCStats: () => request('/api/pqc/stats'),
  getPQCPublicKey: () => request('/api/pqc/public-key'),
}
