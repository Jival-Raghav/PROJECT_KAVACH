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
import Connect          from './pages/Connect'
import Mapping          from './pages/Mapping'
import UnifiedSchemaView from './pages/UnifiedSchema'
import ResolutionView   from './pages/Resolution'
import CaseDetail       from './pages/CaseDetail'
import GraphView        from './pages/GraphView'
import Remediation      from './pages/Remediation'
import ComplianceView   from './pages/Compliance'
import AISecurityView   from './pages/AISecurity'
import {
  Cpu, Loader2, Moon, Play, Shield, Sun, User, MessageSquareText, Network,
  Workflow, Fingerprint, ShieldAlert, FolderSearch, ListChecks, ClipboardCheck, Bot, Layers,
} from 'lucide-react'

/* ── Constants ─────────────────────────────────────────── */

// Grouped by the analyst's journey: bring data in, find risk, dig in, then act.
const NAV_GROUPS = [
  { label: 'Onboard', items: [
    { id: 'autopilot',  label: 'Schema Autopilot',     icon: Workflow,       hint: 'Connect sources, map fields and build the unified schema.' },
    { id: 'resolution', label: 'Identity Resolution',  icon: Fingerprint,    hint: 'Match accounts across systems to one person.' },
  ]},
  { label: 'Detect', items: [
    { id: 'risks',      label: 'Identity Risks',       icon: ShieldAlert,    hint: 'Every identity ranked by fused ML and rule-based risk.' },
    { id: 'clusters',   label: 'Behavior Clusters',    icon: Layers,         hint: 'Peer groups and outliers by access behavior.' },
  ]},
  { label: 'Investigate', items: [
    { id: 'investigate', label: 'Case Investigation',  icon: FolderSearch,   hint: 'Prosecutor vs devil\'s advocate, with a binding final level.' },
    { id: 'graph',       label: 'Access Graph & Paths', icon: Network,       hint: 'Trace privilege paths to crown-jewel resources.' },
  ]},
  { label: 'Respond', items: [
    { id: 'remediation', label: 'Remediation Queue',   icon: ListChecks,     hint: 'Prioritised fixes ready to approve.' },
    { id: 'compliance',  label: 'Posture & Compliance', icon: ClipboardCheck, hint: 'Controls, framework coverage and gaps.' },
    { id: 'security',    label: 'AI & NHI Security',   icon: Bot,            hint: 'Non-human identities and AI agent exposure.' },
  ]},
]
const NAV_ITEMS = NAV_GROUPS.flatMap(g => g.items)

const INSPECTOR_TABS = [
  { id: 'profile',   label: 'Profile',   icon: User },
  { id: 'narrative', label: 'Narrative', icon: MessageSquareText },
  { id: 'impact',    label: 'Impact',    icon: Network },
]

const emptyStats = {
  total_users: 0, critical_count: 0, high_count: 0, review_count: 0,
  suppressed_count: 0, avg_risk_score: 0, top_risky_departments: [],
}

/* ── App ────────────────────────────────────────────────── */

export default function App() {
  /* Theme */
  const [theme, setTheme] = useState(() => localStorage.getItem('kavach-theme-v2') || 'light')

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('kavach-theme-v2', theme)
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
  const [inspectorTab, setInspectorTab]   = useState('profile')
  const [activeTab,    setActiveTab]    = useState('autopilot')
  const [wizardStep,   setWizardStep]   = useState('connect')
  const [ingestedSources, setIngestedSources] = useState([])

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

  // After analyst feedback, refetch so the row, stats and inspector reflect the new suppressed state.
  const onFeedbackChanged = async (userId) => {
    try {
      const [fresh, freshStats] = await Promise.all([getUserRisks(), getStats()])
      setUsers(fresh)
      setStats(freshStats)
      const updated = fresh.find(u => u.user_id === userId)
      if (updated) setSelectedUser(updated)
    } catch (e) {
      console.error('Failed to refresh after feedback:', e)
    }
  }

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
    if (activeTab === 'autopilot') {
      if (wizardStep === 'connect') {
        return (
          <Connect
            sources={ingestedSources}
            setSources={setIngestedSources}
            onNext={() => setWizardStep('mapping')}
          />
        )
      } else if (wizardStep === 'mapping') {
        return (
          <Mapping
            sources={ingestedSources}
            onBack={() => setWizardStep('connect')}
            onNext={() => setWizardStep('unified')}
          />
        )
      } else {
        return (
          <UnifiedSchemaView
            sources={ingestedSources}
            onBack={() => setWizardStep('mapping')}
            onRunComplete={() => {
              setActiveTab('resolution')
              onRunPipeline()
            }}
          />
        )
      }
    }
    if (activeTab === 'resolution') return <ResolutionView />
    if (activeTab === 'investigate') {
      return (
        <CaseDetail
          currentUserId={selectedUser?.user_id || 'USR00173'}
          onSelectUser={(uid) => {
            const found = users.find(u => (u.user_id || u.canonical_id) === uid)
            if (found) setSelectedUser(found)
          }}
        />
      )
    }
    if (activeTab === 'graph') {
      return (
        <GraphView
          selectedAccount={selectedUser?.user_id || 'USR00173'}
          onNavigateToRemediation={() => setActiveTab('remediation')}
        />
      )
    }
    if (activeTab === 'remediation') return <Remediation />
    if (activeTab === 'compliance') return <ComplianceView />
    if (activeTab === 'security') return <AISecurityView />
    if (activeTab === 'org') return <OrgAnomalyPanel anomalies={orgAnomalies} stats={stats} />
    if (activeTab === 'clusters') return <ClusterPanel clusters={clusters} users={users} onSelectUser={setSelectedUser} />
    return <RiskTable users={users} onSelectUser={setSelectedUser} selectedUser={selectedUser} />
  }, [activeTab, wizardStep, ingestedSources, orgAnomalies, users, stats, selectedUser, clusters])

  const isRunning = pipelineStatus === 'running'

  const activeItem = NAV_ITEMS.find(i => i.id === activeTab)

  /* ── Render ─────────────────────────────────────────────── */
  return (
    <div className="app">

      {/* ══════════════════ TOP BAR ══════════════════ */}
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark"><Shield size={16} strokeWidth={2.4} /></span>
          <span className="brand-name display">Kavach</span>
          <span className="brand-sub">Identity threat detection &amp; response</span>
        </div>

        <div className={`run-status ${pipelineStatus}`} aria-live="polite">
          <span className={`status-dot ${pipelineStatus}${isRunning ? ' pulse-dot' : ''}`} />
          <span>
            {isRunning
              ? (pipelineMessage || 'Running…')
              : pipelineStatus === 'complete'
                ? `Ready${lastRun ? ` · ${new Date(lastRun).toLocaleTimeString()}` : ''}`
                : 'Idle'}
          </span>
        </div>

        <div className="topbar-right">
          {llmStatus && (
            <LLMPill
              label="Groq"
              ok={llmStatus.prosecutor?.available && llmStatus.devils_advocate?.available}
              role="Prosecutor + Devil's Advocate"
            />
          )}
          <button
            className="theme-toggle"
            onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')}
            title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
            aria-label="Toggle theme"
          >
            {theme === 'dark' ? <Sun size={14} /> : <Moon size={14} />}
          </button>
          <button id="run-pipeline-btn" onClick={onRunPipeline} disabled={isRunning} className="btn-primary">
            {isRunning ? <Loader2 size={13} className="spin-slow" /> : <Play size={13} />}
            {isRunning ? 'Running…' : 'Run pipeline'}
          </button>
        </div>

        {isRunning && (
          <div className="pipeline-progress">
            <div className="pipeline-progress-fill" style={{ width: `${pipelineProgress}%` }} />
          </div>
        )}
      </header>

      <div className="app-body">

        {/* ══════════════════ SIDEBAR ══════════════════ */}
        <nav className="sidebar" aria-label="Primary">
          {NAV_GROUPS.map(g => (
            <div className="side-group" key={g.label}>
              <div className="side-label">{g.label}</div>
              {g.items.map(({ id, label, icon: Icon }) => (
                <button
                  key={id}
                  className={`side-item${activeTab === id ? ' active' : ''}`}
                  onClick={() => setActiveTab(id)}
                  title={label}
                  aria-current={activeTab === id ? 'page' : undefined}
                >
                  <Icon size={16} />
                  <span>{label}</span>
                </button>
              ))}
            </div>
          ))}

          <div className="side-footer">
            <div className="side-footer-title">Workspace snapshot</div>
            <div className="side-footer-row"><span>Identities</span><b>{stats.total_users ?? 0}</b></div>
            <div className="side-footer-row"><span>Critical</span><b className="crit">{stats.critical_count ?? 0}</b></div>
            <div className="side-footer-row"><span>To review</span><b>{stats.review_count ?? 0}</b></div>
          </div>
        </nav>

        {/* ══════════════════ WORKSPACE ══════════════════ */}
        <div className="workspace">
          <div className="page-head">
            <div className="page-title">
              <h1 className="display">{activeItem?.label || 'Overview'}</h1>
              {activeItem?.hint && <p>{activeItem.hint}</p>}
            </div>
            <div className="kpis">
              <StatCard label="Total users"   value={stats.total_users}                    variant="total"    />
              <StatCard label="Critical"      value={stats.critical_count}                  variant="critical" />
              <StatCard label="High"          value={stats.high_count}                      variant="high"     />
              <StatCard label="To review"     value={stats.review_count}                    variant="review"   />
              <StatCard label="Avg score"     value={stats.avg_risk_score?.toFixed(1) ?? 0} variant="avg"      />
            </div>
          </div>

          <div className="content-area">
            <main className="left-panel">
              {visiblePanel}
            </main>

            {selectedUser && (
              <aside className="right-panel slide-in-right">
                <div className="inspector-tabs" role="tablist">
                  {INSPECTOR_TABS.map(({ id, label, icon: Icon }) => (
                    <button
                      key={id}
                      role="tab"
                      aria-selected={inspectorTab === id}
                      className={`inspector-tab${inspectorTab === id ? ' active' : ''}`}
                      onClick={() => setInspectorTab(id)}
                    >
                      <Icon size={13} /> {label}
                    </button>
                  ))}
                </div>
                <div className="inspector-body">
                  {/* All pages stay mounted so streaming narratives survive tab switches */}
                  <div className="inspector-page" hidden={inspectorTab !== 'profile'}>
                    <UserCard
                      user={selectedUser}
                      onClose={() => setSelectedUser(null)}
                      onInvestigate={(u) => {
                        setSelectedUser(u)
                        setActiveTab('investigate')
                      }}
                    />
                    <FeedbackButtons user={selectedUser} onChanged={onFeedbackChanged} />
                  </div>
                  <div className="inspector-page flush" hidden={inspectorTab !== 'narrative'}>
                    <NarrativePanel user={selectedUser} />
                  </div>
                  <div className="inspector-page" hidden={inspectorTab !== 'impact'}>
                    <BreachImpactPanel user={selectedUser} />
                  </div>
                </div>
                <div className="inspector-foot">Kavach v2 · Enterprise Identity Risk Platform</div>
              </aside>
            )}
          </div>
        </div>
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
      <span className="llm-pill-text">{label}</span>
      <span className={`llm-pill-dot${ok ? ' pulse-dot' : ''}`} />
    </div>
  )
}
