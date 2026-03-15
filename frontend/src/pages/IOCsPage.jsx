import { useState, useEffect } from 'react'
import { api } from '../utils/api'
import { Spinner, Empty } from '../components/UI'

const IOC_TYPES = ['', 'ip', 'domain', 'url', 'hash', 'cve']

const IOC_COLORS = {
  ip: 'text-red-400',
  domain: 'text-blue-400',
  url: 'text-purple-400',
  hash: 'text-yellow-400',
  cve: 'text-green-400',
}

export default function IOCsPage() {
  const [iocs, setIocs] = useState([])
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('')
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)

  const perPage = 50

  useEffect(() => {
    api.iocStats().then(setStats)
  }, [])

  useEffect(() => {
    setLoading(true)
    const params = { page, per_page: perPage }
    if (filter) params.ioc_type = filter
    api.listIocs(params)
      .then(d => { setIocs(d.items); setTotal(d.total) })
      .finally(() => setLoading(false))
  }, [filter, page])

  const handleSearch = async (e) => {
    e.preventDefault()
    if (!search.trim()) return
    setLoading(true)
    api.searchIocs(search)
      .then(results => { setIocs(results); setTotal(results.length) })
      .finally(() => setLoading(false))
  }

  const totalPages = Math.ceil(total / perPage)

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">Indicators of Compromise</h1>
        <p className="text-xs text-gray-500 font-mono mt-0.5">Auto-extracted from ingested threat data</p>
      </div>

      {/* IOC type stats */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {Object.entries(stats.by_type).map(([type, count]) => (
            <button
              key={type}
              onClick={() => { setFilter(filter === type ? '' : type); setPage(1) }}
              className={`card text-left transition-colors ${
                filter === type ? 'border-red-500/50 bg-red-900/10' : 'hover:border-gray-600'
              }`}
            >
              <p className={`text-xs font-mono uppercase font-bold ${IOC_COLORS[type] || 'text-gray-400'}`}>{type}</p>
              <p className="text-xl font-bold text-white font-mono">{count}</p>
            </button>
          ))}
        </div>
      )}

      {/* Search */}
      <form onSubmit={handleSearch} className="flex gap-2">
        <input
          type="text"
          placeholder="Search IPs, domains, hashes..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="flex-1 bg-gray-900 border border-gray-700 text-sm text-gray-200 placeholder-gray-600 rounded-lg px-3 py-2 font-mono outline-none focus:border-red-500 transition-colors"
        />
        <button
          type="submit"
          className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white text-sm font-mono rounded-lg transition-colors"
        >
          Search
        </button>
        {search && (
          <button
            type="button"
            onClick={() => { setSearch(''); setFilter(''); setPage(1) }}
            className="px-3 py-2 bg-gray-800 text-gray-400 text-sm font-mono rounded-lg hover:bg-gray-700 transition-colors"
          >
            Clear
          </button>
        )}
      </form>

      {/* Filter tabs */}
      <div className="flex gap-2 flex-wrap">
        {IOC_TYPES.map(t => (
          <button
            key={t}
            onClick={() => { setFilter(t); setPage(1) }}
            className={`px-3 py-1 text-xs font-mono rounded border transition-colors ${
              filter === t
                ? 'bg-red-600/20 border-red-500/50 text-red-400'
                : 'bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-500'
            }`}
          >
            {t || 'All'}
          </button>
        ))}
      </div>

      {/* IOC Table */}
      {loading ? <Spinner /> : iocs.length === 0 ? (
        <Empty message="No IOCs found" />
      ) : (
        <div className="card overflow-hidden p-0">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800">
                <th className="text-left text-xs font-mono text-gray-500 px-4 py-3 uppercase tracking-wider w-20">Type</th>
                <th className="text-left text-xs font-mono text-gray-500 px-4 py-3 uppercase tracking-wider">Value</th>
                <th className="text-left text-xs font-mono text-gray-500 px-4 py-3 uppercase tracking-wider hidden md:table-cell">Context</th>
              </tr>
            </thead>
            <tbody>
              {iocs.map(ioc => (
                <tr key={ioc.id} className="border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors">
                  <td className="px-4 py-2.5">
                    <span className={`text-xs font-mono font-bold uppercase ${IOC_COLORS[ioc.ioc_type] || 'text-gray-400'}`}>
                      {ioc.ioc_type}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className="text-xs font-mono text-gray-300 break-all">{ioc.value}</span>
                  </td>
                  <td className="px-4 py-2.5 hidden md:table-cell">
                    <span className="text-xs text-gray-600">{ioc.context}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2">
          <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
            className="px-3 py-1.5 text-xs font-mono bg-gray-800 border border-gray-700 rounded disabled:opacity-40 hover:border-gray-500 text-gray-300 transition-colors">
            ← Prev
          </button>
          <span className="text-xs font-mono text-gray-500">Page {page} of {totalPages}</span>
          <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}
            className="px-3 py-1.5 text-xs font-mono bg-gray-800 border border-gray-700 rounded disabled:opacity-40 hover:border-gray-500 text-gray-300 transition-colors">
            Next →
          </button>
        </div>
      )}
    </div>
  )
}
