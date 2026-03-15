import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import ThreatsPage from './pages/ThreatsPage'
import ThreatDetail from './pages/ThreatDetail'
import IOCsPage from './pages/IOCsPage'
import CVEsPage from './pages/CVEsPage'

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/threats" element={<ThreatsPage />} />
        <Route path="/threats/:id" element={<ThreatDetail />} />
        <Route path="/iocs" element={<IOCsPage />} />
        <Route path="/cves" element={<CVEsPage />} />
      </Routes>
    </Layout>
  )
}
