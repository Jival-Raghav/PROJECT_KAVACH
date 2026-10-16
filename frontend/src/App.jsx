import { useEffect, useMemo, useState } from 'react'
import { getOrgAnomalies, getStatus, getStats, getUserRisks, runPipeline } from './api'
import StatusBar from './components/StatusBar'
import RiskTable from './components/RiskTable'
import UserCard from './components/UserCard'
import NarrativePanel from './components/NarrativePanel'
import OrgAnomalyPanel from './components/OrgAnomalyPanel'
import FeedbackButtons from './components/FeedbackButtons'
import BreachImpactPanel from './components/BreachImpactPanel'
import CompliancePanel from './components/CompliancePanel'

const emptyStats = {
  total_users: 0,
  critical_count: 0,
  high_count: 0,
  review_count: 0,
  suppressed_count: 0,
  avg_risk_score: 0,
  top_risky_departments: []
}

export default function App() {
  const [pipelineStatus, setPipelineStatus] = useState('idle')
  const [pipelineProgress, setPipelineProgress] = useState(0)
  const [pipelineMessage, setPipelineMessage] = useState('')
  const [users, setUsers] = useState([])
  const [stats, setStats] = useState(emptyStats)
  const [selectedUser, setSelectedUser] = useState(null)
  const [activeTab, setActiveTab] = useState('risks')
  const [orgAnomalies, setOrgAnomalies] = useState([])

  const loadDashboard = async () => {
    const [loadedUsers, loadedStats, loadedOrgAnomalies] = await Promise.all([
      getUserRisks(),
      getStats(),
      getOrgAnomalies()
    ])
    setUsers(loadedUsers)
    setStats(loadedStats)
    setOrgAnomalies(loadedOrgAnomalies)
  }

  useEffect(() => {
    let cancelled = false

    const syncStatus = async () => {
      const status = await getStatus()
      if (cancelled) {
        return
      }
      setPipelineStatus(status.status)
      setPipelineProgress(status.progress || 0)
      setPipelineMessage(status.message || '')
      if (status.status === 'complete') {
        await loadDashboard()
      }
    }

    syncStatus()
    const timer = setInterval(syncStatus, 5000)

    return () => {
      cancelled = true
      clearInterval(timer)
    }
  }, [])

  const onRunPipeline = async () => {
    await runPipeline()
  }

  const visiblePanel = useMemo(() => {
    if (activeTab === 'org') {
      return <OrgAnomalyPanel anomalies={orgAnomalies} />
    }
    if (activeTab === 'compliance') {
      return <CompliancePanel users={users} />
    }
    return <RiskTable users={users} onSelectUser={setSelectedUser} />
  }, [activeTab, orgAnomalies, users])

  return (
    <div className="min-h-screen px-4 py-6 text-slate-100 md:px-8">
      <div className="mx-auto flex max-w-7xl flex-col gap-6">
        <StatusBar
          status={pipelineStatus}
          progress={pipelineProgress}
          message={pipelineMessage}
          onRunPipeline={onRunPipeline}
        />

        <section className="grid gap-4 md:grid-cols-5">
          <StatCard label="Total Users" value={stats.total_users} accent="from-cyan-400 to-blue-500" />
          <StatCard label="Critical" value={stats.critical_count} accent="from-rose-400 to-red-500" />
          <StatCard label="High" value={stats.high_count} accent="from-amber-300 to-orange-500" />
          <StatCard label="Review" value={stats.review_count} accent="from-emerald-300 to-lime-500" />
          <StatCard label="Avg Score" value={stats.avg_risk_score?.toFixed ? stats.avg_risk_score.toFixed(1) : stats.avg_risk_score} accent="from-sky-300 to-indigo-500" />
        </section>

        <div className="flex flex-wrap gap-3 rounded-3xl border border-white/10 bg-slate-950/60 p-2 shadow-2xl shadow-cyan-950/20 backdrop-blur">
          {[
            ['risks', 'Risk Table'],
            ['org', 'Org Anomalies'],
            ['compliance', 'Compliance']
          ].map(([key, label]) => (
            <button
              key={key}
              onClick={() => setActiveTab(key)}
              className={`rounded-2xl px-4 py-2 text-sm font-medium transition ${
                activeTab === key ? 'bg-cyan-400 text-slate-950' : 'bg-white/5 text-slate-200 hover:bg-white/10'
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        <div className="grid gap-6 xl:grid-cols-[1fr_360px]">
          <main className="overflow-hidden rounded-[2rem] border border-white/10 bg-slate-950/70 p-4 shadow-2xl shadow-slate-950/30 backdrop-blur">
            {visiblePanel}
          </main>

          <aside className="space-y-4">
            <NarrativePanel user={selectedUser} />
            <BreachImpactPanel user={selectedUser} />
            <FeedbackButtons user={selectedUser} />
            {selectedUser ? <UserCard user={selectedUser} onClose={() => setSelectedUser(null)} /> : null}
          </aside>
        </div>
      </div>
    </div>
  )
}

function StatCard({ label, value, accent }) {
  return (
    <div className="rounded-3xl border border-white/10 bg-slate-950/70 p-4 shadow-xl shadow-slate-950/25">
      <div className={`mb-3 h-1.5 rounded-full bg-gradient-to-r ${accent}`} />
      <div className="text-xs uppercase tracking-[0.3em] text-slate-400">{label}</div>
      <div className="mt-2 text-3xl font-semibold text-white">{value}</div>
    </div>
  )
}
