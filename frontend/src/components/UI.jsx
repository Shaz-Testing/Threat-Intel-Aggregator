// SeverityBadge
export function SeverityBadge({ severity }) {
  return (
    <span className={`severity-badge severity-${severity || 'NONE'}`}>
      {severity || 'N/A'}
    </span>
  )
}

// SourceBadge
export function SourceBadge({ source }) {
  const colors = {
    nvd: 'text-blue-400 border-blue-800 bg-blue-900/20',
    exploitdb: 'text-red-400 border-red-800 bg-red-900/20',
    otx: 'text-purple-400 border-purple-800 bg-purple-900/20',
    mitre: 'text-yellow-400 border-yellow-800 bg-yellow-900/20',
  }
  const cls = colors[source] || 'text-gray-400 border-gray-700 bg-gray-800'
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono uppercase tracking-wider border ${cls}`}>
      {source}
    </span>
  )
}

// RiskScoreBar
export function RiskScoreBar({ score }) {
  const pct = (score / 10) * 100
  const color =
    score >= 9 ? 'bg-red-500' :
    score >= 7 ? 'bg-orange-500' :
    score >= 4 ? 'bg-yellow-500' : 'bg-green-500'

  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-gray-800 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs font-mono text-gray-400 w-7 text-right">{score}</span>
    </div>
  )
}

// StatCard
export function StatCard({ label, value, sub, accent }) {
  return (
    <div className="stat-card">
      <p className="text-xs text-gray-500 font-mono uppercase tracking-wider">{label}</p>
      <p className={`text-2xl font-bold font-mono ${accent || 'text-white'}`}>{value ?? '—'}</p>
      {sub && <p className="text-xs text-gray-500">{sub}</p>}
    </div>
  )
}

// Loading spinner
export function Spinner() {
  return (
    <div className="flex items-center justify-center py-16">
      <div className="w-8 h-8 border-2 border-gray-700 border-t-red-500 rounded-full animate-spin" />
    </div>
  )
}

// Empty state
export function Empty({ message = 'No data found' }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-gray-600">
      <span className="text-4xl mb-3">🔍</span>
      <p className="font-mono text-sm">{message}</p>
    </div>
  )
}

// Tag chips
export function Tags({ tags = [] }) {
  if (!tags.length) return null
  return (
    <div className="flex flex-wrap gap-1">
      {tags.map(tag => (
        <span key={tag} className="px-1.5 py-0.5 bg-gray-800 text-gray-400 text-xs font-mono rounded border border-gray-700">
          {tag}
        </span>
      ))}
    </div>
  )
}
