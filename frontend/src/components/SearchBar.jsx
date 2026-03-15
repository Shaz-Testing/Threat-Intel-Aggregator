import { useSearch } from '../hooks/useThreats'
import { Link } from 'react-router-dom'
import { SeverityBadge } from './UI'

export default function SearchBar() {
  const { query, setQuery, results, loading } = useSearch()

  return (
    <div className="relative">
      <div className="flex items-center gap-2 bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 focus-within:border-red-500 transition-colors">
        <span className="text-gray-500 text-sm">🔍</span>
        <input
          type="text"
          placeholder="Search threats, CVEs, tags..."
          value={query}
          onChange={e => setQuery(e.target.value)}
          className="flex-1 bg-transparent text-sm text-gray-200 placeholder-gray-600 outline-none font-mono"
        />
        {loading && (
          <span className="text-xs text-gray-600 font-mono">searching...</span>
        )}
      </div>

      {/* Dropdown results */}
      {results && results.length > 0 && (
        <div className="absolute top-full left-0 right-0 mt-1 bg-gray-900 border border-gray-700 rounded-lg shadow-xl z-50 max-h-80 overflow-auto">
          {results.map(t => (
            <Link
              key={t.id}
              to={`/threats/${t.id}`}
              onClick={() => setQuery('')}
              className="flex items-center gap-3 px-4 py-3 hover:bg-gray-800 transition-colors border-b border-gray-800 last:border-0"
            >
              <SeverityBadge severity={t.severity} />
              <span className="text-sm text-gray-300 truncate flex-1">{t.title}</span>
              {t.cve_id && (
                <span className="text-xs font-mono text-blue-400 shrink-0">{t.cve_id}</span>
              )}
            </Link>
          ))}
        </div>
      )}

      {results && results.length === 0 && query.length >= 2 && (
        <div className="absolute top-full left-0 right-0 mt-1 bg-gray-900 border border-gray-700 rounded-lg shadow-xl z-50 px-4 py-3 text-sm text-gray-500 font-mono">
          No results for "{query}"
        </div>
      )}
    </div>
  )
}
