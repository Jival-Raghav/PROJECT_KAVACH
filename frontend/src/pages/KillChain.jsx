import { useCallback, useEffect, useState } from 'react'
import { AlertTriangle, ChevronRight, Loader2, Play, RefreshCw } from 'lucide-react'
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

  return (
    <div className="kc-page">
      <div className="kc-toolbar">
        <div className="kc-kpis">
          <Kpi label="Events analysed" value={(meta.ingest?.lines_parsed ?? 0).toLocaleString()} />
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

export function KillChainRules() {
  const [rules, setRules] = useState([])
  useEffect(() => { getKillchainRules().then(setRules).catch(() => {}) }, [])
  return (
    <div className="kc-page">
      <div className="card kc-note">
        Rules live in <code>config/detection_rules/*.yaml</code>. Add or tune a rule by editing YAML
        (SQL <code>where</code> or a Sigma-style <code>selection</code>), then press
        <b> Re-run detection</b> — no code change.
      </div>
      <div className="card kc-table-wrap">
        <table className="kc-table static">
          <thead><tr><th>ID</th><th>Title</th><th>ATT&amp;CK</th><th>Kind</th><th>Severity</th></tr></thead>
          <tbody>
            {rules.map(r => (
              <tr key={r.id}>
                <td className="mono">{r.id}</td><td>{r.title}</td>
                <td className="mono">{r.technique}</td><td>{r.kind}</td>
                <td><SeverityBadge severity={r.severity} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
