import { useEffect, useState } from 'react'
import { getActors } from '../api'

export function ActorTable({ actors }) {
  return (
    <table className="kc-table static compact">
      <thead><tr><th>Accounts</th><th>Source IPs</th><th>Countries</th><th>Proven by</th><th>Incidents</th></tr></thead>
      <tbody>
        {actors.map(a => (
          <tr key={a.actor_id}>
            <td className="mono">{a.users.join(', ')}</td>
            <td className="mono">{a.ips.map(ip => <div key={ip}>{ip}</div>)}</td>
            <td>{a.countries.join(', ') || '-'}</td>
            <td>
              {a.evidence.map(e => (
                <div key={`${e.user}|${e.ip}|${e.kind}`}>
                  {e.kind.replace('_', ' ')}: {e.user} from {e.ip} × {e.events.toLocaleString()}
                </div>
              ))}
              {a.accounts_created.map(c => (
                <div key={c.account}>{c.creator} created account {c.account}</div>
              ))}
            </td>
            <td className="mono">{a.incident_ids.map(i => `#${i}`).join(', ') || '-'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

export default function Actors() {
  const [actors, setActors] = useState([])
  const [error, setError] = useState('')

  useEffect(() => { getActors().then(setActors).catch(e => setError(String(e))) }, [])

  return (
    <div className="kc-page">
      <div className="card kc-note">
        One actor across IPs and accounts, linked only by successful logins, configuration changes
        and account creation. Failed logins never link anything.
      </div>
      {error && <div className="kc-error">{error}</div>}
      <div className="card kc-table-wrap"><ActorTable actors={actors} /></div>
    </div>
  )
}
