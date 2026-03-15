import { Link } from 'react-router-dom'
import { SeverityBadge, SourceBadge, RiskScoreBar, Tags } from './UI'

export default function ThreatCard({ threat }) {
  const published = threat.published_at
    ? new Date(threat.published_at).toLocaleDateString()
    : null

  return (
    <Link to={`/threats/${threat.id}`} className="block card hover:border-gray-600 transition-colors group">
      {/* Header row */}
      <div className="flex items-start justify-between gap-3 mb-2">
        <div className="flex items-center gap-2 flex-wrap">
          <SeverityBadge severity={threat.severity} />
          <SourceBadge source={threat.source} />
          {threat.cve_id && (
            <span className="text-xs font-mono text-blue-400">{threat.cve_id}</span>
          )}
        </div>
        {published && (
          <span className="text-xs text-gray-600 font-mono shrink-0">{published}</span>
        )}
      </div>

      {/* Title */}
      <h3 className="text-sm font-semibold text-gray-200 group-hover:text-white mb-1 line-clamp-2">
        {threat.title}
      </h3>

      {/* AI summary or description */}
      <p className="text-xs text-gray-500 line-clamp-2 mb-3">
        {threat.ai_summary || threat.description}
      </p>

      {/* Risk score */}
      <RiskScoreBar score={threat.risk_score} />

      {/* Tags */}
      {threat.ai_tags?.length > 0 && (
        <div className="mt-2">
          <Tags tags={threat.ai_tags.slice(0, 4)} />
        </div>
      )}

      {/* Remediation priority */}
      {threat.ai_remediation_priority && (
        <div className="mt-2">
          <span className={`text-xs font-mono font-bold ${
            threat.ai_remediation_priority === 'PATCH_NOW' ? 'text-red-400' :
            threat.ai_remediation_priority === 'MONITOR' ? 'text-yellow-400' : 'text-green-400'
          }`}>
            ● {threat.ai_remediation_priority.replace('_', ' ')}
          </span>
        </div>
      )}
    </Link>
  )
}
