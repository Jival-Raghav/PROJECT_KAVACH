import { useEffect, useState } from 'react'
import { getCompliance } from '../api'

export const CONTROL_STATUS = { gap: 'Gap', attempted: 'Attempted, blocked', no_failure_seen: 'No failure seen' }

export function ControlTable({ controls }) {
  return (
    <table className="kc-table static compact">
      <thead><tr><th>Control</th><th>Standards</th><th>Status</th><th>Incidents</th></tr></thead>
      <tbody>
        {controls.map(c => (
          <tr key={c.id}>
            <td>{c.title}</td>
            <td className="kc-muted">{c.refs.join(' · ')}</td>
            <td>{CONTROL_STATUS[c.status] || c.status}</td>
            <td className="mono">{[...c.failed_in, ...c.attempted_in].map(i => `#${i}`).join(', ') || '-'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

export default function ControlFindings() {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => { getCompliance().then(setData).catch(e => setError(String(e))) }, [])

  return (
    <div className="kc-page">
      {error && <div className="kc-error">{error}</div>}
      {data && (
        <>
          <div className="card kc-note">{data.notice}</div>
          <div className="card kc-table-wrap"><ControlTable controls={data.controls} /></div>
        </>
      )}
    </div>
  )
}
