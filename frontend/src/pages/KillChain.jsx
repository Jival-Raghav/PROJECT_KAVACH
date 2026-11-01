import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  AlertTriangle, ChevronRight, CircleDot, FileCode2, Fingerprint, Gauge, Loader2, Play,
  RefreshCw, Route, Search,
} from 'lucide-react'
import { getIncidents, getKillchainRules, getKillchainStatus, runKillchain } from '../api'
import IncidentDetail from './IncidentDetail'

export const STAGES = [
  'Reconnaissance', 'Weaponization', 'Delivery', 'Exploitation',
  'Installation', 'Command and Control', 'Actions on Objectives',
]

export function SeverityBadge({ severity, score }) {
  const cls = { critical: 'badge-critical', high: 'badge-review', medium: 'badge-info' }[severity] || 'badge-neutral'
  return <span className={cls}>{severity}{score != null ? ` · ${Math.round(score)}` : ''}</span>
}

export function StageStrip({ stages }) {
  return (
    <div className="kc-stage-strip" title={stages.join(' → ')}>
      {STAGES.map(s => (
        <span key={s} className={`kc-stage${stages.includes(s) ? ' on' : ''}`} title={s} />
      ))}
    </div>
  )
}

function Kpi({ label, value }) {
  return (
    <div className="kc-kpi">
      <div className="kc-kpi-value">{value}</div>
      <div className="kc-kpi-label">{label}</div>
    </div>
  )
}

export default function KillChain() {
  const [incidents, setIncidents] = useState([])
  const [status, setStatus] = useState(null)
  const [selected, setSelected] = useState(null)
  const [error, setError] = useState('')

  const load = useCallback(() => {
    getIncidents().then(setIncidents).catch(e => setError(String(e)))
    getKillchainStatus().then(setStatus).catch(() => {})
  }, [])

  useEffect(load, [load])

  useEffect(() => {
    if (status?.status !== 'running') return
    const t = setInterval(() => getKillchainStatus().then(s => {
      setStatus(s)
      if (s.status !== 'running') load()
    }), 1500)
    return () => clearInterval(t)
  }, [status?.status, load])

  const start = () => runKillchain(true).then(() => setStatus(s => ({ ...s, status: 'running', stage: 'starting' })))
    .catch(e => setError(String(e)))

  if (selected != null) {
    return <IncidentDetail incidentId={selected} onBack={() => setSelected(null)} />
  }

  const meta = status?.run_meta || {}
  const running = status?.status === 'running'
  const critical = incidents.filter(i => i.severity === 'critical').length
  const stalled = (meta.clock_stalls || []).reduce((sum, s) => sum + s.lines, 0)
  const analysed = (meta.ingest?.lines_parsed ?? 0) - stalled

  return (
    <div className="kc-page">
      <div className="kc-toolbar">
        <div className="kc-kpis">
          <Kpi label="Events analysed" value={analysed.toLocaleString()} />
          <Kpi label="Raw alerts merged" value={(meta.raw_alerts_merged ?? 0).toLocaleString()} />
          <Kpi label="Incidents" value={incidents.length} />
          <Kpi label="Critical" value={critical} />
        </div>
        <div className="kc-actions">
          <button className="btn-ghost" onClick={load}><RefreshCw size={13} /> Refresh</button>
          <button className="btn-primary" onClick={start} disabled={running}>
            {running ? <Loader2 size={13} className="spin-slow" /> : <Play size={13} />}
            {running ? `Running: ${status?.stage || ''}` : 'Re-run detection'}
          </button>
        </div>
      </div>

      {meta.ingest && (
        <div className="card kc-note">
          <b>What we found in {meta.log_path?.split(/[\\/]/).pop() || 'the log'}:</b> {meta.ingest.lines_read.toLocaleString()} lines read.{' '}
          {meta.ingest.lines_skipped.toLocaleString()} were unreadable and skipped.{' '}
          {stalled.toLocaleString()} share one frozen timestamp, so they are counted but kept out of
          detection. The remaining {analysed.toLocaleString()} events produced {incidents.length} incidents.
        </div>
      )}

      {meta.schema_reviewed === false && (
        <div className="kc-error">
          <AlertTriangle size={14} /> This log is not FortiGate. Kavach learned its format automatically and nobody has
          reviewed that yet, so outcomes and risk scores may be wrong. Approve the schema after checking it.
        </div>
      )}
      {error && <div className="kc-error"><AlertTriangle size={14} /> {error}</div>}
      {status?.status === 'error' && <div className="kc-error"><AlertTriangle size={14} /> {status.error}</div>}

      {incidents.length === 0 ? (
        <div className="card kc-empty">
          No incidents yet. Run <code>python -m killchain.cli run</code> in <code>backend/</code>,
          or press <b>Re-run detection</b>.
        </div>
      ) : (
        <div className="card kc-table-wrap">
          <table className="kc-table">
            <thead>
              <tr>
                <th>#</th><th>Risk</th><th>Incident</th><th>Kill chain</th>
                <th>Tactics</th><th>Alerts merged</th><th>First seen</th><th />
              </tr>
            </thead>
            <tbody>
              {incidents.map(i => (
                <tr key={i.incident_id} onClick={() => setSelected(i.incident_id)}>
                  <td className="mono">{i.incident_id}</td>
                  <td><SeverityBadge severity={i.severity} score={i.risk_score} /></td>
                  <td className="kc-title">{i.title}</td>
                  <td><StageStrip stages={i.stages} /></td>
                  <td>{i.tactics.map(t => <span key={t} className="chip kc-chip">{t}</span>)}</td>
                  <td className="mono">{i.raw_alert_count.toLocaleString()} → 1</td>
                  <td className="mono kc-muted">{i.first_seen.replace('T', ' ').slice(0, 16)}</td>
                  <td><ChevronRight size={14} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

const KIND_META = {
  match: { label: 'Match', icon: CircleDot, help: 'Fires on every event matching the condition.' },
  threshold: { label: 'Threshold', icon: Gauge, help: 'Fires once a count of matching events crosses a limit in a time window.' },
  rare_for_entity: { label: 'Rare for entity', icon: Fingerprint, help: 'Fires when a value is unusual for that specific entity’s own history.' },
  sequence: { label: 'Sequence', icon: Route, help: 'Fires when two conditions happen in order, within a time window.' },
}
const KINDS = ['', 'match', 'threshold', 'rare_for_entity', 'sequence']

function RuleCard({ r }) {
  const [open, setOpen] = useState(false)
  const meta = KIND_META[r.kind] || {}
  const Icon = meta.icon || CircleDot
  const hasSelection = r.selection && Object.keys(r.selection).length > 0
  return (
    <article className="card rl-card">
      <button className="rl-card-top" onClick={() => setOpen(o => !o)} aria-expanded={open}>
        <SeverityBadge severity={r.severity} />
        <span className="rl-id mono">{r.id}</span>
        <span className="rl-title">{r.title}</span>
        <span className="chip kc-chip mono">{r.technique}</span>
        <span className="rl-kind" title={meta.help}><Icon size={13} /> {meta.label || r.kind}</span>
        <ChevronRight size={15} className={`rl-chevron${open ? ' open' : ''}`} />
      </button>
      {open && (
        <div className="rl-detail">
          <p className="kc-muted">{meta.help}</p>
          <div className="rl-code-label">where</div>
          <pre className="rl-code">{r.where || 'TRUE'}</pre>
          {hasSelection && (
            <>
              <div className="rl-code-label">selection</div>
              <pre className="rl-code">{JSON.stringify(r.selection, null, 1)}</pre>
            </>
          )}
        </div>
      )}
    </article>
  )
}

export function KillChainRules() {
  const [rules, setRules] = useState([])
  const [kind, setKind] = useState('')
  const [q, setQ] = useState('')
  useEffect(() => { getKillchainRules().then(setRules).catch(() => {}) }, [])
  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return rules.filter(r => (!kind || r.kind === kind)
      && (!needle || r.title.toLowerCase().includes(needle) || r.id.toLowerCase().includes(needle)
        || r.technique.toLowerCase().includes(needle)))
  }, [rules, kind, q])
  return (
    <div className="kc-page">
      <div className="card kc-note">
        <FileCode2 size={16} className="an-note-icon" />
        <div>
          Rules live in <code>config/detection_rules/*.yaml</code>. Add or tune a rule by editing
          YAML (SQL <code>where</code> or a Sigma-style <code>selection</code>), then press
          <b> Re-run detection</b> — no code change. Click a rule to see what it actually checks.
        </div>
      </div>

      <div className="an-toolbar">
        <div className="an-kinds">
          {KINDS.map(k => (
            <button key={k} className={kind === k ? 'on' : ''} onClick={() => setKind(k)}>
              {k ? (KIND_META[k]?.label || k) : 'All'}
            </button>
          ))}
        </div>
        <div className="an-search">
          <Search size={13} />
          <input value={q} onChange={e => setQ(e.target.value)} placeholder="Filter by id, title or technique" />
        </div>
        <span className="kc-muted" style={{ marginLeft: 'auto' }}>{shown.length} of {rules.length} rules</span>
      </div>

      <div className="rl-list">
        {shown.map(r => <RuleCard key={r.id} r={r} />)}
      </div>
    </div>
  )
}
