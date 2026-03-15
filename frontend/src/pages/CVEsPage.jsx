import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../utils/api'
import { SeverityBadge, RiskScoreBar, Spinner, Empty } from '../components/UI'

export default function CVEsPage() {
  const [cves, setCves] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.latestCves(50).then(setCves).finally(() => setLoading(false))
  }, [])

  if (loading) return <Spinner />

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">Latest CVEs</h1>
        <p className="text-xs text-gray-500 font-mono mt-0.5">Most recently published CVEs from NVD</p>
      </div>

      {cves.length === 0 ? (
        <Empty message="No CVEs yet — run a scrape to populate" />
      ) : (
        <div className="card overflow-hidden p-0">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800">
                <th className="text-left text-xs font-mono text-gray-500 px-4 py-3 uppercase tracking-wider">CVE ID</th>
                <th className="text-left text-xs font-mono text-gray-500 px-4 py-3 uppercase tracking-wider">Severity</th>
                <th className="text-left text-xs font-mono text-gray-500 px-4 py-3 uppercase tracking-wider hidden md:table-cell">Summary</th>
                <th className="text-left text-xs font-mono text-gray-500 px-4 py-3 uppercase tracking-wider">Risk</th>
                <th className="text-left text-xs font-mono text-gray-500 px-4 py-3 uppercase tracking-wider hidden lg:table-cell">Published</th>
              </tr>
            </thead>
            <tbody>
              {cves.map(cve => (
                <tr key={cve.id} className="border-b border-gray-800/50 hover:bg-gray-800/40 transition-colors">
                  <td className="px-4 py-3">
                    <Link to={`/threats/${cve.id}`} className="text-blue-400 hover:text-blue-300 font-mono text-xs font-bold">
                      {cve.cve_id}
                    </Link>
                  </td>
                  <td className="px-4 py-3">
                    <SeverityBadge severity={cve.severity} />
                  </td>
                  <td className="px-4 py-3 hidden md:table-cell">
                    <p className="text-xs text-gray-400 line-clamp-2 max-w-sm">
                      {cve.ai_summary || cve.description}
                    </p>
                  </td>
                  <td className="px-4 py-3 w-32">
                    <RiskScoreBar score={cve.risk_score} />
                  </td>
                  <td className="px-4 py-3 hidden lg:table-cell">
                    <span className="text-xs text-gray-600 font-mono">
                      {cve.published_at ? new Date(cve.published_at).toLocaleDateString() : '—'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
