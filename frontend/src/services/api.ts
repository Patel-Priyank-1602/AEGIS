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
}
