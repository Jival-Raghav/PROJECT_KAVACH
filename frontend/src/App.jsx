import { useEffect, useMemo, useState } from 'react'
import { getOrgAnomalies, getStatus, getStats, getUserRisks, runPipeline, getLlmStatus } from './api'
import StatusBar from './components/StatusBar'
import RiskTable from './components/RiskTable'
import UserCard from './components/UserCard'
import NarrativePanel from './components/NarrativePanel'
import OrgAnomalyPanel from './components/OrgAnomalyPanel'
import FeedbackButtons from './components/FeedbackButtons'
import BreachImpactPanel from './components/BreachImpactPanel'
import CompliancePanel from './components/CompliancePanel'

const emptyStats = {
  total_users: 0, critical_count: 0, high_count: 0, review_count: 0,
  suppressed_count: 0, avg_risk_score: 0, top_risky_departments: []
}

export default function App() {
  const [pipelineStatus, setPipelineStatus] = useState('idle')
  const [pipelineProgress, setPipelineProgress] = useState(0)
  const [pipelineMessage, setPipelineMessage] = useState('')
  const [lastRun, setLastRun] = useState(null)
  
  const [llmStatus, setLlmStatus] = useState(null)
  const [users, setUsers] = useState([])
  const [stats, setStats] = useState(emptyStats)
  const [orgAnomalies, setOrgAnomalies] = useState([])
  
  const [selectedUser, setSelectedUser] = useState(null)
  const [activeTab, setActiveTab] = useState('risks')

  const loadDashboard = async () => {
    try {
      const [loadedUsers, loadedStats, loadedOrgAnomalies, loadedLlmStatus] = await Promise.all([
        getUserRisks(), getStats(), getOrgAnomalies(), getLlmStatus()
      ])
      setUsers(loadedUsers)
      setStats(loadedStats)
      setOrgAnomalies(loadedOrgAnomalies)
      setLlmStatus(loadedLlmStatus)
    } catch (e) {
      console.error('Failed to load dashboard:', e)
    }
  }

  // Initial load
  useEffect(() => { loadDashboard() }, [])

  // Pipeline polling
  useEffect(() => {
    let timer = null
    const syncStatus = async () => {
      try {
        const s = await getStatus()
        setPipelineStatus(s.status)
        setPipelineProgress(s.progress || 0)
        setPipelineMessage(s.message || '')
        
        if (s.status === 'complete' && pipelineStatus !== 'complete') {
          setLastRun(Date.now())
          await loadDashboard()
        }
      } catch (e) {
        console.error('Status sync error:', e)
      }
    }
    timer = setInterval(syncStatus, 3000)
    return () => clearInterval(timer)
  }, [pipelineStatus])

  const onRunPipeline = async () => {
    try {
      await runPipeline()
      setPipelineStatus('running')
    } catch (e) {
      console.error('Failed to start pipeline:', e)
    }
  }

  const visiblePanel = useMemo(() => {
    if (activeTab === 'org')        return <OrgAnomalyPanel anomalies={orgAnomalies} stats={stats} />
    if (activeTab === 'compliance') return <CompliancePanel users={users} />
    return <RiskTable users={users} onSelectUser={setSelectedUser} selectedUser={selectedUser} />
  }, [activeTab, orgAnomalies, users, stats, selectedUser])

  return (
    <div className="min-h-screen px-4 py-8 text-slate-100 md:px-8">
      {/* Background decoration */}
      <div className="fixed inset-0 pointer-events-none z-[-1] bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-cyan-900/20 via-[#05070f] to-[#05070f]"></div>

      <div className="mx-auto flex max-w-[1400px] flex-col gap-6">
        <StatusBar
          status={pipelineStatus}
          progress={pipelineProgress}
          message={pipelineMessage}
          onRunPipeline={onRunPipeline}
          llmStatus={llmStatus}
          lastRun={lastRun}
        />

        <section className="grid gap-4 sm:grid-cols-2 md:grid-cols-5">
          <StatCard label="Total Users" value={stats.total_users} accent="from-cyan-400 to-blue-500" />
          <StatCard label="Critical Risk" value={stats.critical_count} accent="from-rose-400 to-red-500" />
          <StatCard label="High Risk" value={stats.high_count} accent="from-orange-400 to-amber-500" />
          <StatCard label="To Review" value={stats.review_count} accent="from-emerald-300 to-teal-500" />
          <StatCard label="Avg Score" value={stats.avg_risk_score?.toFixed(1) || 0} accent="from-indigo-400 to-purple-500" />
        </section>

        {/* Tab switcher */}
        <div className="inline-flex flex-wrap gap-2 rounded-2xl border border-white/10 bg-slate-900/60 p-1.5 shadow-xl backdrop-blur max-w-fit">
          {[
            { id: 'risks', label: 'Identity Risks' },
            { id: 'org', label: 'Org Anomalies' },
            { id: 'compliance', label: 'Compliance Gaps' }
          ].map(t => (
            <button
              key={t.id}
              onClick={() => setActiveTab(t.id)}
              className={`rounded-xl px-5 py-2 text-sm font-semibold transition ${
                activeTab === t.id
                  ? 'bg-gradient-to-b from-white/10 to-transparent text-white shadow-sm ring-1 ring-white/20'
                  : 'text-slate-400 hover:bg-white/5 hover:text-slate-200'
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>

        <div className="grid gap-6 xl:grid-cols-[1fr_400px] items-start">
          <main className="glass overflow-hidden rounded-[2rem] p-5 shadow-2xl min-h-[600px] flex flex-col">
            {visiblePanel}
          </main>

          <aside className="sticky top-6 flex flex-col gap-4">
            <UserCard user={selectedUser} onClose={() => setSelectedUser(null)} />
            <NarrativePanel user={selectedUser} />
            <BreachImpactPanel user={selectedUser} />
            <FeedbackButtons user={selectedUser} />
          </aside>
        </div>
      </div>
    </div>
  )
}

function StatCard({ label, value, accent }) {
  return (
    <div className="glass group relative overflow-hidden rounded-[2rem] p-5 transition hover:border-white/20 hover:shadow-2xl">
      <div className={`absolute inset-0 bg-gradient-to-br ${accent} opacity-0 transition-opacity group-hover:opacity-5`} />
      <div className={`mb-4 h-1.5 w-12 rounded-full bg-gradient-to-r ${accent}`} />
      <div className="text-[10px] uppercase tracking-[0.3em] text-slate-400">{label}</div>
      <div className="mt-1 text-4xl font-bold tracking-tight text-white">{value}</div>
    </div>
  )
}
