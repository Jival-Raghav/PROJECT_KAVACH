import { useEffect, useRef, useState } from 'react'
import { ArrowLeft, Clock, FileText, Layers, LayoutDashboard, Loader2, Radiation, Route, Scale } from 'lucide-react'
import { getIncident } from '../api'
import { useRun } from '../run'
import { SeverityBadge } from './KillChain'
import AttackPathTab from './incident/AttackPathTab'
import BlastRadiusTab from './incident/BlastRadiusTab'
import OtherInfoTab from './incident/OtherInfoTab'
import OverviewTab from './incident/OverviewTab'
import ReportTab from './incident/ReportTab'
import ReviewTab from './incident/ReviewTab'
import TimelineTab from './incident/TimelineTab'
import { fmtTime } from './incident/format'

const TABS = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard, blurb: 'The short version' },
  { id: 'timeline', label: 'Timeline', icon: Clock, blurb: 'Every step in order, with its evidence' },
  { id: 'path', label: 'Attack Path', icon: Route, blurb: 'What took part and how it connects' },
  { id: 'blast', label: 'Blast Radius (What If?)', icon: Radiation, blurb: 'What the attacker could reach next' },
  { id: 'review', label: "Devil's Advocate", icon: Scale, blurb: 'The case for and against, and the verdict' },
  { id: 'report', label: 'Incident Report', icon: FileText, blurb: 'A written summary to share' },
  { id: 'other', label: 'Other Info', icon: Layers, blurb: 'What to do, controls, unusual behaviour and actors' },
]

export default function IncidentDetail({ incidentId, onBack, onNavigate }) {
  const { generation } = useRun()
  const [inc, setInc] = useState(null)
  const [report, setReport] = useState(null)
  const [review, setReview] = useState(null)
  const [tab, setTab] = useState('overview')
  const [error, setError] = useState('')
  const [withdrawn, setWithdrawn] = useState(false)
  const firstGen = useRef(true)

  // A merged incident hands over to the one it was merged into; a withdrawn one gets a notice.
  const handleGone = e => {
    if (e?.detail?.merged_into != null) { onNavigate?.(e.detail.merged_into); return true }
    if (e?.detail?.withdrawn) { setWithdrawn(true); return true }
    return false
  }

  useEffect(() => {
    setInc(null)
    setTab('overview')
    setWithdrawn(false)
    getIncident(incidentId)
      .then(d => { setInc(d); setReport(d.report); setReview(d.review) })
      .catch(e => { if (!handleGone(e)) setError(String(e)) })
  }, [incidentId])

  // New live data: refetch quietly, keep the tab, and keep any LLM-written report or review.
  useEffect(() => {
    if (firstGen.current) { firstGen.current = false; return }
    getIncident(incidentId)
      .then(d => {
        setInc(d)
        setReport(r => (r && r.generated_by !== 'template' ? r : d.report))
        setReview(r => (r && r.generated_by !== 'template' ? r : d.review))
      })
      .catch(e => { handleGone(e) })
  }, [generation])

  if (withdrawn) {
    return (
      <div className="kc-page">
        <header className="kc-inc-head">
          <button className="btn-ghost" onClick={onBack}><ArrowLeft size={13} /> All incidents</button>
        </header>
        <div className="card kc-note">This incident was withdrawn after more data arrived.</div>
      </div>
    )
  }

  if (error) return <div className="kc-error">{error}</div>
  if (!inc) return <div className="kc-empty"><Loader2 size={16} className="spin-slow" /> Loading incident…</div>

  return (
    <div className="kc-page">
      <header className="kc-inc-head">
        <button className="btn-ghost" onClick={onBack}><ArrowLeft size={13} /> All incidents</button>
        <div className="kc-inc-title">
          <h2>#{inc.incident_id} · {inc.title}</h2>
          <div className="kc-detail-meta">
            <SeverityBadge severity={inc.severity} score={inc.risk_score} />
            <span className="kc-muted">{fmtTime(inc.first_seen)} → {fmtTime(inc.last_seen)}</span>
          </div>
        </div>
      </header>

      <nav className="kc-tabs" role="tablist" aria-label="Incident sections">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button key={id} role="tab" aria-selected={tab === id} className={tab === id ? 'on' : ''} onClick={() => setTab(id)}>
            <Icon size={14} /> {label}
          </button>
        ))}
      </nav>

      {tab === 'overview' && <OverviewTab inc={inc} />}
      {tab === 'timeline' && <TimelineTab inc={inc} />}
      {tab === 'path' && <AttackPathTab inc={inc} />}
      {tab === 'blast' && <BlastRadiusTab inc={inc} />}
      {tab === 'review' && <ReviewTab incidentId={inc.incident_id} review={review} onReview={setReview} />}
      {tab === 'report' && <ReportTab incidentId={inc.incident_id} report={report} onReport={setReport} />}
      {tab === 'other' && <OtherInfoTab inc={inc} />}
    </div>
  )
}
