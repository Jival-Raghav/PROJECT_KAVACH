import { useEffect, useMemo, useState } from 'react'
import { getClusterSummary, getOrgAnomalies, getStatus, getStats, getUserRisks, runPipeline, getLlmStatus } from './api'
import RiskTable        from './components/RiskTable'
import UserCard         from './components/UserCard'
import NarrativePanel   from './components/NarrativePanel'
import OrgAnomalyPanel  from './components/OrgAnomalyPanel'
import FeedbackButtons  from './components/FeedbackButtons'
import BreachImpactPanel from './components/BreachImpactPanel'
import CompliancePanel  from './components/CompliancePanel'
import ClusterPanel     from './components/ClusterPanel'
import { Cpu, Loader2, Moon, Play, Shield, Sun } from 'lucide-react'

/* ── Constants ─────────────────────────────────────────── */

const TABS = [
  { id: 'risks',      label: 'Identity Risks' },
  { id: 'org',        label: 'Org Anomalies' },
  { id: 'compliance', label: 'Compliance Gaps' },
  { id: 'clusters',   label: 'Behavior Clusters' },
]

const emptyStats = {
  total_users: 0, critical_count: 0, high_count: 0, review_count: 0,
  suppressed_count: 0, avg_risk_score: 0, top_risky_departments: [],
}

/* ── App ────────────────────────────────────────────────── */

export default function App() {
  /* Theme */
  const [theme, setTheme] = useState(() => localStorage.getItem('ispad-theme') || 'dark')

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('ispad-theme', theme)
  }, [theme])

  /* Pipeline state */
  const [pipelineStatus,   setPipelineStatus]   = useState('idle')
  const [pipelineProgress, setPipelineProgress] = useState(0)
  const [pipelineMessage,  setPipelineMessage]  = useState('')
  const [lastRun,          setLastRun]          = useState(null)

  /* Data state */
  const [llmStatus,    setLlmStatus]    = useState(null)
  const [users,        setUsers]        = useState([])
  const [stats,        setStats]        = useState(emptyStats)
  const [orgAnomalies, setOrgAnomalies] = useState([])
  const [clusters,     setClusters]     = useState([])

  /* UI state */
  const [selectedUser, setSelectedUser] = useState(null)
  const [activeTab,    setActiveTab]    = useState('risks')

  /* ── Data loading ──────────────────────────────────────── */
  const loadDashboard = async () => {
    try {
      const [loadedUsers, loadedStats, loadedOrgAnomalies, loadedLlmStatus, loadedClusters] =
        await Promise.allSettled([
          getUserRisks(), getStats(), getOrgAnomalies(), getLlmStatus(), getClusterSummary(),
        ])
      setUsers(       loadedUsers.status        === 'fulfilled' ? loadedUsers.value        : [])
      setStats(       loadedStats.status        === 'fulfilled' ? loadedStats.value        : emptyStats)
      setOrgAnomalies(loadedOrgAnomalies.status === 'fulfilled' ? loadedOrgAnomalies.value : [])
      setLlmStatus(   loadedLlmStatus.status    === 'fulfilled' ? loadedLlmStatus.value    : null)
      setClusters(    loadedClusters.status     === 'fulfilled' ? loadedClusters.value     : [])
    } catch (e) {
      console.error('Failed to load dashboard:', e)
    }
  }

  useEffect(() => { loadDashboard() }, [])

  /* ── Pipeline polling ───────────────────────────────────── */
  useEffect(() => {
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
    const timer = setInterval(syncStatus, 3000)
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

  /* ── Tab content ────────────────────────────────────────── */
  const visiblePanel = useMemo(() => {
    if (activeTab === 'org')        return <OrgAnomalyPanel anomalies={orgAnomalies} stats={stats} />
    if (activeTab === 'compliance') return <CompliancePanel users={users} />
    if (activeTab === 'clusters')   return <ClusterPanel clusters={clusters} users={users} onSelectUser={setSelectedUser} />
    return <RiskTable users={users} onSelectUser={setSelectedUser} selectedUser={selectedUser} />
  }, [activeTab, orgAnomalies, users, stats, selectedUser, clusters])

  const isRunning = pipelineStatus === 'running'

  /* ── Render ─────────────────────────────────────────────── */
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', overflow: 'hidden', background: 'var(--bg)' }}>

      {/* ── SG red stripe ── */}
      <div className="sg-stripe" />

      {/* ══════════════════ NAV BAR ══════════════════ */}
      <nav className="nav-bar">

        {/* Left: Logo + subtitle + status */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0, flexShrink: 0 }}>
          <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            width: 28, height: 28, borderRadius: 4, background: 'var(--sg-red)', flexShrink: 0,
          }}>
            <Shield size={14} color="#ffffff" strokeWidth={2.5} />
          </div>
          <div style={{ minWidth: 0 }}>
            <div className="nav-logo">ISPAD</div>
            <div className="nav-subtitle">Identity Sprawl &amp; Privilege Abuse Detection</div>
          </div>
          {/* Status dot */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginLeft: 8, flexShrink: 0 }}>
            <span className={`status-dot ${pipelineStatus}${isRunning ? ' pulse-dot' : ''}`} />
            <span style={{ fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
              {isRunning
                ? (pipelineMessage || 'Running…')
                : pipelineStatus === 'complete'
                  ? `Ready · ${lastRun ? new Date(lastRun).toLocaleTimeString() : ''}`
                  : 'Idle'}
            </span>
          </div>
        </div>

        {/* Center: Tab navigation */}
        <div className="nav-tabs" style={{ flex: 1, justifyContent: 'center' }}>
          {TABS.map(t => (
            <button
              key={t.id}
              className={`nav-tab${activeTab === t.id ? ' active' : ''}`}
              onClick={() => setActiveTab(t.id)}
            >
              {t.label}
            </button>
          ))}
        </div>

        {/* Right: LLM pills + theme toggle + run button */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
          {llmStatus && (
            <>
              <LLMPill label="LM Studio" ok={llmStatus.prosecutor?.available}      role="Prosecutor" />
              <LLMPill label="Ollama"    ok={llmStatus.devils_advocate?.available}  role="Devil's Advocate" />
            </>
          )}

          <button
            className="theme-toggle"
            onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')}
            title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          >
            {theme === 'dark' ? <Sun size={14} /> : <Moon size={14} />}
          </button>

          <button
            id="run-pipeline-btn"
            onClick={onRunPipeline}
            disabled={isRunning}
            className="btn-primary"
          >
            {isRunning ? <Loader2 size={13} className="spin-slow" /> : <Play size={13} />}
            {isRunning ? 'Running…' : 'Run Pipeline'}
          </button>
        </div>

        {/* Progress bar at bottom of nav when running */}
        {isRunning && (
          <div className="pipeline-progress">
            <div className="pipeline-progress-fill" style={{ width: `${pipelineProgress}%` }} />
          </div>
        )}
      </nav>

      {/* ══════════════════ STAT BAR ══════════════════ */}
      <div className="stat-bar">
        <StatCard label="Total Users"   value={stats.total_users}                    variant="total"    />
        <StatCard label="Critical Risk" value={stats.critical_count}                  variant="critical" />
        <StatCard label="High Risk"     value={stats.high_count}                      variant="high"     />
        <StatCard label="To Review"     value={stats.review_count}                    variant="review"   />
        <StatCard label="Avg Score"     value={stats.avg_risk_score?.toFixed(1) ?? 0} variant="avg"      />
      </div>

      {/* ══════════════════ CONTENT AREA ══════════════════ */}
      <div className="content-area">

        {/* Left panel — scrollable tab content */}
        <main className="left-panel">
          {visiblePanel}
        </main>

        {/* Right panel — slides in when a user is selected */}
        {selectedUser && (
          <aside className="right-panel slide-in-right">
            <UserCard        user={selectedUser} onClose={() => setSelectedUser(null)} />
            <NarrativePanel  user={selectedUser} />
            <BreachImpactPanel user={selectedUser} />
            <FeedbackButtons user={selectedUser} />
            <div style={{ paddingTop: 4, textAlign: 'center', fontSize: 10, color: 'var(--text-muted)' }}>
              Powered by Société Générale Hackathon
            </div>
          </aside>
        )}
      </div>
    </div>
  )
}

/* ── Stat Card ─────────────────────────────────────────── */
function StatCard({ label, value, variant }) {
  return (
    <div className={`stat-card ${variant}`}>
      <div>
        <div className="stat-card-label">{label}</div>
        <div className="stat-card-value">{value}</div>
      </div>
    </div>
  )
}

/* ── LLM Status Pill ───────────────────────────────────── */
function LLMPill({ label, ok, role }) {
  return (
    <div title={role} className={`llm-pill${ok ? ' online' : ''}`}>
      <Cpu size={10} />
      {label}
      <span className={`llm-pill-dot${ok ? ' pulse-dot' : ''}`} />
    </div>
  )
}
