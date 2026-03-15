import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import { api } from '../utils/api'
import { SeverityBadge, SourceBadge, RiskScoreBar, Tags, Spinner } from '../components/UI'

export default function ThreatDetail() {
  const { id } = useParams()
  const [threat, setThreat] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.getThreat(id).then(setThreat).finally(() => setLoading(false))
  }, [id])

  if (loading) return <Spinner />
  if (!threat) return <div className="p-6 text-gray-500 font-mono">Threat not found</div>

  return (
    <div className="p-6 max-w-4xl space-y-6">
      {/* Back */}
      <Link to="/threats" className="text-xs text-gray-500 hover:text-gray-300 font-mono">
        ← Back to threats
      </Link>

      {/* Header */}
      <div className="card space-y-3">
        <div className="flex items-center gap-2 flex-wrap">
          <SeverityBadge severity={threat.severity} />
          <SourceBadge source={threat.source} />
          {threat.cve_id && (
            <span className="text-sm font-mono text-blue-400 font-bold">{threat.cve_id}</span>
          )}
        </div>
        <h1 className="text-lg font-bold text-white">{threat.title}</h1>
        <div className="flex items-center gap-4 text-xs text-gray-500 font-mono">
          <span>CVSS: <span className="text-gray-300">{threat.cvss_score || 'N/A'}</span></span>
          <span>Risk Score: <span className="text-gray-300">{threat.risk_score}</span></span>
          {threat.published_at && (
            <span>Published: <span className="text-gray-300">{new Date(threat.published_at).toLocaleDateString()}</span></span>
          )}
        </div>
        <RiskScoreBar score={threat.risk_score} />
        {threat.url && (
          <a href={threat.url} target="_blank" rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-xs text-red-400 hover:text-red-300 font-mono">
            View source ↗
          </a>
        )}
      </div>

      {/* AI Analysis */}
      {threat.ai_summary && (
        <div className="card border-red-900/40 bg-red-950/10">
          <div className="flex items-center gap-2 mb-3">
            <span className="text-red-400">🤖</span>
            <h2 className="text-sm font-semibold text-red-300">AI Analysis</h2>
            {threat.ai_remediation_priority && (
              <span className={`ml-auto text-xs font-mono font-bold ${
                threat.ai_remediation_priority === 'PATCH_NOW' ? 'text-red-400' :
                threat.ai_remediation_priority === 'MONITOR' ? 'text-yellow-400' : 'text-green-400'
              }`}>
                ● {threat.ai_remediation_priority.replace('_', ' ')}
              </span>
            )}
          </div>
          <p className="text-sm text-gray-300 leading-relaxed">{threat.ai_summary}</p>
        </div>
      )}

      {/* Tags & Products */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {threat.ai_tags?.length > 0 && (
          <div className="card">
            <h2 className="text-xs font-semibold text-gray-500 font-mono uppercase mb-3">Threat Tags</h2>
            <Tags tags={threat.ai_tags} />
          </div>
        )}
        {threat.ai_affected_products?.length > 0 && (
          <div className="card">
            <h2 className="text-xs font-semibold text-gray-500 font-mono uppercase mb-3">Affected Products</h2>
            <Tags tags={threat.ai_affected_products} />
          </div>
        )}
        {threat.ai_mitre_techniques?.length > 0 && (
          <div className="card">
            <h2 className="text-xs font-semibold text-gray-500 font-mono uppercase mb-3">MITRE ATT&CK</h2>
            <Tags tags={threat.ai_mitre_techniques} />
          </div>
        )}
        {threat.cwe_ids?.length > 0 && (
          <div className="card">
            <h2 className="text-xs font-semibold text-gray-500 font-mono uppercase mb-3">CWE IDs</h2>
            <Tags tags={threat.cwe_ids} />
          </div>
        )}
      </div>

      {/* Raw description */}
      <div className="card">
        <h2 className="text-xs font-semibold text-gray-500 font-mono uppercase mb-3">Raw Description</h2>
        <p className="text-sm text-gray-400 leading-relaxed whitespace-pre-wrap">{threat.description}</p>
      </div>

      {/* IOCs */}
      {threat.iocs?.length > 0 && (
        <div className="card">
          <h2 className="text-sm font-semibold text-gray-300 mb-4">
            Extracted IOCs <span className="text-gray-600 font-mono text-xs ml-1">({threat.iocs.length})</span>
          </h2>
          <div className="space-y-2">
            {threat.iocs.map(ioc => (
              <div key={ioc.id} className="flex items-center gap-3 py-2 border-b border-gray-800 last:border-0">
                <span className="text-xs font-mono text-gray-500 uppercase w-14 shrink-0">{ioc.ioc_type}</span>
                <span className="text-xs font-mono text-gray-300 flex-1 break-all">{ioc.value}</span>
                {ioc.context && (
                  <span className="text-xs text-gray-600">{ioc.context}</span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
