const BASE = import.meta.env.VITE_API_URL || '/api'

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!res.ok) throw new Error(`API error ${res.status}: ${await res.text()}`)
  return res.json()
}

export const api = {
  // Threats
  listThreats: (params = {}) => {
    const q = new URLSearchParams(params).toString()
    return request(`/threats${q ? '?' + q : ''}`)
  },
  getThreat: (id) => request(`/threats/${id}`),
  searchThreats: (q) => request(`/threats/search?q=${encodeURIComponent(q)}`),
  getStats: () => request('/threats/stats'),

  // CVEs
  latestCves: (limit = 20) => request(`/cves/latest?limit=${limit}`),

  // IOCs
  listIocs: (params = {}) => {
    const q = new URLSearchParams(params).toString()
    return request(`/iocs${q ? '?' + q : ''}`)
  },
  iocStats: () => request('/iocs/stats'),
  searchIocs: (q) => request(`/iocs/search?q=${encodeURIComponent(q)}`),

  // Scraper
  triggerScrape: () => request('/scrape/trigger', { method: 'POST' }),

  // Health
  health: () => request('/health'),
}
