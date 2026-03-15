import { useState, useEffect, useCallback } from 'react'
import { api } from '../utils/api'

export function useThreats(params = {}) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const key = JSON.stringify(params)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    api.listThreats(params)
      .then(d => { if (!cancelled) { setData(d); setError(null) } })
      .catch(e => { if (!cancelled) setError(e.message) })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [key])

  return { data, loading, error }
}

export function useStats(refreshInterval = 30000) {
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(() => {
    api.getStats().then(setStats).catch(console.error).finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    load()
    const id = setInterval(load, refreshInterval)
    return () => clearInterval(id)
  }, [load, refreshInterval])

  return { stats, loading, reload: load }
}

export function useSearch(debounceMs = 300) {
  const [query, setQuery] = useState('')
  const [results, setResults] = useState(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (query.length < 2) { setResults(null); return }
    setLoading(true)
    const id = setTimeout(() => {
      api.searchThreats(query)
        .then(d => setResults(d.items))
        .catch(console.error)
        .finally(() => setLoading(false))
    }, debounceMs)
    return () => clearTimeout(id)
  }, [query, debounceMs])

  return { query, setQuery, results, loading }
}
