import { useEffect, useState } from 'react'
import {
  Bot, ClipboardCheck, Crosshair, FileCode2, Fingerprint, ListChecks, Moon, PlayCircle, Radar, Shield, Sun,
} from 'lucide-react'
import KillChain, { KillChainRules } from './pages/KillChain'
import Anomalies from './pages/Anomalies'
import Actors from './pages/Actors'
import Accounts from './pages/Accounts'
import ResponsePlan from './pages/ResponsePlan'
import ControlFindings from './pages/ControlFindings'
import { RunProvider, useRun } from './run'
import RunSelector from './pages/live/RunSelector'
import LiveBar from './pages/live/LiveBar'

// In the order an analyst works: find the attack, understand who, then respond.
const NAV_GROUPS = [
  { label: 'Detect', items: [
    { id: 'incidents', label: 'Attack Incidents', icon: Crosshair, page: KillChain, hint: 'Firewall logs turned into ranked, MITRE-labelled attack paths: timeline, graph, reach, review and response.' },
    { id: 'anomalies', label: 'Anomalies', icon: Radar, page: Anomalies, hint: 'Unusual hosts, IPs and users outside any incident. Leads to look at, not confirmed attacks.' },
    { id: 'rules', label: 'Detection Rules', icon: FileCode2, page: KillChainRules, hint: 'YAML / Sigma-style rules mapped to ATT&CK. Edit config, not code.' },
  ]},
  { label: 'Investigate', items: [
    { id: 'actors', label: 'Actors', icon: Fingerprint, page: Actors, hint: 'One actor across source IPs and accounts, linked by proven activity only.' },
    { id: 'accounts', label: 'Accounts & LLM Safety', icon: Bot, page: Accounts, hint: 'Service, shared and person accounts proven active in the log, and prompt-injection checks on log text.' },
  ]},
  { label: 'Respond', items: [
    { id: 'response', label: 'Response Plan', icon: ListChecks, page: ResponsePlan, hint: 'Proposed actions to approve. Exported as a dry-run script, never run by Kavach.' },
    { id: 'controls', label: 'Control Findings', icon: ClipboardCheck, page: ControlFindings, hint: 'Security controls that this log shows failing or being tested.' },
  ]},
]
const NAV_ITEMS = NAV_GROUPS.flatMap(g => g.items)

export default function App() {
  return <RunProvider><AppShell /></RunProvider>
}

function AppShell() {
  const { runId } = useRun()
  const [theme, setTheme] = useState(() => localStorage.getItem('kavach-theme-v2') || 'light')
  const [activeTab, setActiveTab] = useState('incidents')

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('kavach-theme-v2', theme)
  }, [theme])

  const active = NAV_ITEMS.find(i => i.id === activeTab)
  const Page = active.page

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark"><Shield size={16} strokeWidth={2.4} /></span>
          <span className="brand-name display">Kavach</span>
          <span className="brand-sub">Firewall kill-chain analysis</span>
        </div>
        <div className="topbar-right">
          <a
            className="btn-ghost demo-link"
            href="https://drive.google.com/file/d/1GfeoTYjAO9I07pSrY4oQCMZ1rlvyFGef/view?usp=drive_link"
            target="_blank"
            rel="noopener noreferrer"
            title="Watch the demo video"
          >
            <PlayCircle size={14} /> Watch demo
          </a>
          <RunSelector />
          <button
            className="theme-toggle"
            onClick={() => setTheme(t => (t === 'dark' ? 'light' : 'dark'))}
            title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
            aria-label="Toggle theme"
          >
            {theme === 'dark' ? <Sun size={14} /> : <Moon size={14} />}
          </button>
        </div>
      </header>

      <div className="app-body">
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
        </nav>

        <div className="workspace">
          <div className="page-head">
            <div className="page-title">
              <h1 className="display">{active.label}</h1>
              <p>{active.hint}</p>
            </div>
          </div>
          <LiveBar />
          <div className="content-area">
            <main className="left-panel"><Page key={runId} /></main>
          </div>
        </div>
      </div>
    </div>
  )
}
