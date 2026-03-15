import { NavLink } from 'react-router-dom'
import { useState } from 'react'
import { api } from '../utils/api'

const NAV = [
  { to: '/',        label: 'Dashboard',  icon: '⬛' },
  { to: '/threats', label: 'Threats',    icon: '🛡️' },
  { to: '/cves',    label: 'CVEs',       icon: '🔍' },
  { to: '/iocs',    label: 'IOCs',       icon: '📡' },
]

export default function Layout({ children }) {
  const [scraping, setScraping] = useState(false)
  const [msg, setMsg] = useState('')

  const handleScrape = async () => {
    setScraping(true)
    setMsg('')
    try {
      await api.triggerScrape()
      setMsg('Scrape started!')
    } catch {
      setMsg('Error triggering scrape')
    } finally {
      setScraping(false)
      setTimeout(() => setMsg(''), 3000)
    }
  }

  return (
    <div className="flex h-screen overflow-hidden">
      {/* Sidebar */}
      <aside className="w-56 bg-gray-900 border-r border-gray-800 flex flex-col shrink-0">
        {/* Logo */}
        <div className="px-4 py-5 border-b border-gray-800">
          <div className="flex items-center gap-2">
            <span className="text-red-500 text-xl">⚠</span>
            <div>
              <p className="text-sm font-bold text-white leading-none">ThreatIQ</p>
              <p className="text-xs text-gray-500 font-mono">intel aggregator</p>
            </div>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-2 py-4 space-y-1">
          {NAV.map(({ to, label, icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
                  isActive
                    ? 'bg-red-500/10 text-red-400 font-medium'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800'
                }`
              }
            >
              <span>{icon}</span>
              {label}
            </NavLink>
          ))}
        </nav>

        {/* Scrape button */}
        <div className="px-3 py-4 border-t border-gray-800">
          <button
            onClick={handleScrape}
            disabled={scraping}
            className="w-full py-2 px-3 bg-red-600 hover:bg-red-500 disabled:bg-gray-700 disabled:text-gray-500 text-white text-xs font-mono font-bold rounded transition-colors"
          >
            {scraping ? '⏳ Scraping...' : '▶ Run Scrape Now'}
          </button>
          {msg && <p className="text-xs text-green-400 mt-1 text-center font-mono">{msg}</p>}
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 overflow-auto bg-gray-950">
        {children}
      </main>
    </div>
  )
}
