import { useEffect, useState } from 'react'
import { getAccounts, getLlmSafety } from '../api'

export default function Accounts() {
  const [rows, setRows] = useState([])
  const [safety, setSafety] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    getAccounts().then(setRows).catch(e => setError(String(e)))
    getLlmSafety().then(setSafety).catch(() => {})
  }, [])

  return (
    <div className="kc-page">
      <div className="card kc-note">
        Accounts proven active by a successful login or a configuration change. Names seen only in
        failed logins are guesses, not accounts. Service and shared types are inferred from the name.
      </div>
      {error && <div className="kc-error">{error}</div>}
      {safety && (
        <div className="card kc-section">
          <h3>LLM safety</h3>
          <p>
            Scanned {safety.evidence_items_scanned.toLocaleString()} evidence items from {safety.incidents_scanned} incidents
            for prompt injection before any LLM can see them.
            {' '}{safety.incidents_with_suspected_injection.length === 0
              ? 'None found in this log.'
              : `Redacted suspected injection in ${safety.incidents_with_suspected_injection.length} incident(s).`}
          </p>
          <div className="kc-muted">Attack verdicts are computed by a fixed rule, so log text and LLM answers cannot change them.</div>
        </div>
      )}
      <div className="card kc-table-wrap">
        <table className="kc-table static compact">
          <thead><tr><th>Account</th><th>Type</th><th>Source IPs</th><th>VPN</th><th>Admin</th><th>Changes</th><th>Findings</th><th>Incidents</th></tr></thead>
          <tbody>
            {rows.map(r => (
              <tr key={r.account}>
                <td className="mono">{r.account}</td>
                <td>{r.type}</td>
                <td className="mono">{r.ips.map(ip => <div key={ip}>{ip}</div>)}</td>
                <td className="mono">{r.vpn_logins.toLocaleString()}</td>
                <td className="mono">{r.admin_logins}</td>
                <td className="mono">{r.config_changes}</td>
                <td>{r.findings.map(f => <div key={f.code}><b>{f.severity}:</b> {f.text}</div>)}</td>
                <td className="mono">{r.incident_ids.map(i => `#${i}`).join(', ') || '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
