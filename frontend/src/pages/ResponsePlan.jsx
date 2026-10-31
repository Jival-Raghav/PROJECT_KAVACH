import { useCallback, useEffect, useState } from 'react'
import { exportResponseScript, getResponseActions, getResponseAudit, moveResponseAction } from '../api'

const NEXT = {
  proposed: [['approved', 'Approve'], ['rejected', 'Reject']],
  approved: [['rejected', 'Reject']],
  rejected: [['proposed', 'Reopen']],
  exported: [],
}

export default function ResponsePlan() {
  const [actions, setActions] = useState([])
  const [audit, setAudit] = useState([])
  const [script, setScript] = useState('')
  const [error, setError] = useState('')

  const load = useCallback(() => {
    getResponseActions().then(setActions).catch(e => setError(String(e)))
    getResponseAudit().then(setAudit).catch(() => {})
  }, [])

  useEffect(load, [load])

  const move = (id, to) => moveResponseAction(id, to).then(load).catch(e => setError(String(e)))
  const exportNow = () => exportResponseScript().then(text => { setScript(text); load() })
    .catch(e => setError(String(e)))
  const approved = actions.filter(a => a.status === 'approved').length

  return (
    <div className="kc-page">
      <div className="card kc-note">
        Proposed actions from the incidents. Kavach never changes the firewall: approved actions are
        only exported as a dry-run script for a person to review.
      </div>
      {error && <div className="kc-error">{error}</div>}
      <div className="kc-actions">
        <button className="btn-primary" onClick={exportNow} disabled={!approved}>
          Export {approved} approved as dry-run script
        </button>
      </div>
      {script && <div className="card kc-section"><h3>Dry-run script</h3><pre className="mono">{script}</pre></div>}
      <div className="card kc-table-wrap">
        <table className="kc-table static">
          <thead><tr><th>Action</th><th>Why</th><th>Incidents</th><th>Status</th><th /></tr></thead>
          <tbody>
            {actions.map(a => (
              <tr key={a.action_id}>
                <td>{a.title}</td>
                <td>{a.why}</td>
                <td className="mono">{a.incident_ids.map(i => `#${i}`).join(', ')}</td>
                <td>{a.status}</td>
                <td>
                  {NEXT[a.status].map(([to, label]) => (
                    <button key={to} className="btn-ghost" onClick={() => move(a.action_id, to)}>{label}</button>
                  ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {audit.length > 0 && (
        <div className="card kc-section">
          <h3>Audit trail</h3>
          {[...audit].reverse().slice(0, 30).map((e, i) => (
            <div key={i} className="mono kc-muted">{e.timestamp} {e.actor}: {e.action_id} {e.from} → {e.to}</div>
          ))}
        </div>
      )}
    </div>
  )
}
