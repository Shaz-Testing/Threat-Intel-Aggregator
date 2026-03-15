import { useState } from 'react'
import { useThreats } from '../hooks/useThreats'
import ThreatCard from '../components/ThreatCard'
import SearchBar from '../components/SearchBar'
import { Spinner, Empty } from '../components/UI'

const SEVERITIES = ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
const SOURCES = ['', 'nvd', 'exploitdb', 'otx', 'mitre']

export default function ThreatsPage() {
  const [severity, setSeverity] = useState('')
  const [source, setSource] = useState('')
  const [page, setPage] = useState(1)

  const { data, loading } = useThreats({ severity: severity || undefined, source: source || undefined, page, per_page: 24 })

  const totalPages = data ? Math.ceil(data.total / 24) : 1

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">All Threats</h1>
          {data && <p className="text-xs text-gray-500 font-mono mt-0.5">{data.total} threats total</p>}
        </div>
      </div>

      <SearchBar />

      {/* Filters */}
      <div className="flex gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          <label className="text-xs text-gray-500 font-mono">Severity:</label>
          <select
            value={severity}
            onChange={e => { setSeverity(e.target.value); setPage(1) }}
            className="text-xs bg-gray-800 border border-gray-700 text-gray-300 rounded px-2 py-1 font-mono outline-none focus:border-red-500"
          >
            {SEVERITIES.map(s => <option key={s} value={s}>{s || 'All'}</option>)}
          </select>
        </div>
        <div className="flex items-center gap-2">
          <label className="text-xs text-gray-500 font-mono">Source:</label>
          <select
            value={source}
            onChange={e => { setSource(e.target.value); setPage(1) }}
            className="text-xs bg-gray-800 border border-gray-700 text-gray-300 rounded px-2 py-1 font-mono outline-none focus:border-red-500"
          >
            {SOURCES.map(s => <option key={s} value={s}>{s || 'All'}</option>)}
          </select>
        </div>
      </div>

      {/* Grid */}
      {loading ? <Spinner /> : data?.items?.length ? (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {data.items.map(t => <ThreatCard key={t.id} threat={t} />)}
        </div>
      ) : (
        <Empty message="No threats found" />
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2 pt-4">
          <button
            onClick={() => setPage(p => Math.max(1, p - 1))}
            disabled={page === 1}
            className="px-3 py-1.5 text-xs font-mono bg-gray-800 border border-gray-700 rounded disabled:opacity-40 hover:border-gray-500 text-gray-300 transition-colors"
          >
            ← Prev
          </button>
          <span className="text-xs font-mono text-gray-500">
            Page {page} of {totalPages}
          </span>
          <button
            onClick={() => setPage(p => Math.min(totalPages, p + 1))}
            disabled={page === totalPages}
            className="px-3 py-1.5 text-xs font-mono bg-gray-800 border border-gray-700 rounded disabled:opacity-40 hover:border-gray-500 text-gray-300 transition-colors"
          >
            Next →
          </button>
        </div>
      )}
    </div>
  )
}
