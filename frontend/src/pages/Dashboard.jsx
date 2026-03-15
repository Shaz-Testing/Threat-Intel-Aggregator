import { useStats } from '../hooks/useThreats'
import { StatCard, Spinner, SeverityBadge, SourceBadge, RiskScoreBar } from '../components/UI'
import SearchBar from '../components/SearchBar'
import { Link } from 'react-router-dom'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend
} from 'recharts'

const SEVERITY_COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
}

const SOURCE_COLORS = {
  nvd: '#3b82f6',
  exploitdb: '#ef4444',
  otx: '#a855f7',
  mitre: '#eab308',
}

export default function Dashboard() {
  const { stats, loading, reload } = useStats(30000)

  if (loading) return <Spinner />

  const severityData = stats
    ? Object.entries(stats.by_severity).map(([name, value]) => ({ name, value }))
    : []

  const sourceData = stats
    ? Object.entries(stats.by_source).map(([name, value]) => ({ name, value }))
    : []

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Threat Intelligence Dashboard</h1>
          <p className="text-xs text-gray-500 font-mono mt-0.5">
            AI-powered aggregation · auto-refreshes every 30s
          </p>
        </div>
        <button
          onClick={reload}
          className="text-xs text-gray-400 hover:text-white font-mono px-3 py-1.5 bg-gray-800 rounded border border-gray-700 hover:border-gray-500 transition-colors"
        >
          ↻ Refresh
        </button>
      </div>

      {/* Search */}
      <SearchBar />

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Total Threats" value={stats?.total_threats ?? 0} accent="text-white" />
        <StatCard label="Critical" value={stats?.by_severity?.CRITICAL ?? 0} accent="text-red-400" />
        <StatCard label="High" value={stats?.by_severity?.HIGH ?? 0} accent="text-orange-400" />
        <StatCard label="Medium" value={stats?.by_severity?.MEDIUM ?? 0} accent="text-yellow-400" />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Severity bar chart */}
        <div className="card">
          <h2 className="text-sm font-semibold text-gray-300 mb-4">Threats by Severity</h2>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={severityData} barSize={32}>
              <XAxis dataKey="name" tick={{ fill: '#6b7280', fontSize: 11, fontFamily: 'monospace' }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#6b7280', fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={{ background: '#111827', border: '1px solid #374151', borderRadius: 6, fontSize: 12 }}
                cursor={{ fill: 'rgba(255,255,255,0.03)' }}
              />
              <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                {severityData.map((entry) => (
                  <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] || '#6b7280'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Source pie chart */}
        <div className="card">
          <h2 className="text-sm font-semibold text-gray-300 mb-4">Threats by Source</h2>
          <ResponsiveContainer width="100%" height={180}>
            <PieChart>
              <Pie
                data={sourceData}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                outerRadius={65}
                innerRadius={35}
                paddingAngle={3}
              >
                {sourceData.map((entry) => (
                  <Cell key={entry.name} fill={SOURCE_COLORS[entry.name] || '#6b7280'} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ background: '#111827', border: '1px solid #374151', borderRadius: 6, fontSize: 12 }}
              />
              <Legend
                iconType="circle"
                iconSize={8}
                formatter={(v) => <span style={{ color: '#9ca3af', fontSize: 11, fontFamily: 'monospace' }}>{v}</span>}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Top threats */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-gray-300">Top Threats by Risk Score</h2>
          <Link to="/threats" className="text-xs text-red-400 hover:text-red-300 font-mono">
            View all →
          </Link>
        </div>
        <div className="space-y-3">
          {stats?.top_threats?.length ? stats.top_threats.map(t => (
            <Link key={t.id} to={`/threats/${t.id}`} className="block hover:bg-gray-800 -mx-2 px-2 py-2 rounded transition-colors">
              <div className="flex items-center gap-3 mb-1">
                <SeverityBadge severity={t.severity} />
                <SourceBadge source={t.source} />
                <span className="text-sm text-gray-300 flex-1 truncate">{t.title}</span>
              </div>
              <RiskScoreBar score={t.risk_score} />
            </Link>
          )) : (
            <p className="text-sm text-gray-600 font-mono py-4 text-center">
              No threats yet — run a scrape to populate
            </p>
          )}
        </div>
      </div>
    </div>
  )
}
