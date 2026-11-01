import { useEffect, useState } from 'react'
import { Fingerprint, Globe2, Key, Link2, Siren, User, X } from 'lucide-react'
import { getActors } from '../api'
import { useRun } from '../run'

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

// A deterministic colour + initials "identicon" from the actor's own id, not random.
function hashColor(seed) {
  let h = 0
  for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) >>> 0
  const hue = h % 360
  return `hsl(${hue} 70% 45%)`
}
function initials(a) {
  const name = a.users[0] || a.ips[0] || '?'
  return name.replace(/[^A-Za-z0-9]/g, '').slice(0, 2).toUpperCase() || '?'
}

function ActorCard({ a, onOpen }) {
  const color = hashColor(a.actor_id)
  return (
    <button className="ac-card" style={{ '--ac-color': color }} onClick={() => onOpen(a)}>
      <span className="ac-avatar">{initials(a)}</span>
      <span className="ac-name mono">{a.users[0] || a.ips[0]}</span>
      {a.users.length > 1 && <span className="kc-muted">+{a.users.length - 1} more account{a.users.length > 2 ? 's' : ''}</span>}
      <span className="ac-stats">
        <span><Key size={11} /> {a.users.length}</span>
        <span><Globe2 size={11} /> {a.ips.length}</span>
        {a.incident_ids.length > 0 && <span className="ac-incidents"><Siren size={11} /> {a.incident_ids.length}</span>}
      </span>
    </button>
  )
}

function ActorModal({ a, onClose }) {
  const color = hashColor(a.actor_id)
  return (
    <div className="ac-overlay" onClick={onClose}>
      <div className="card ac-modal" style={{ '--ac-color': color }} onClick={e => e.stopPropagation()}>
        <button className="ac-close" onClick={onClose} aria-label="Close"><X size={16} /></button>
        <div className="ac-modal-head">
          <span className="ac-avatar large">{initials(a)}</span>
          <div>
            <h3>{a.users[0] || a.ips[0]}</h3>
            <p className="kc-muted">Linked by successful logins, configuration changes or account creation.</p>
          </div>
        </div>

        <div className="ac-section">
          <h4><Key size={13} /> Accounts ({a.users.length})</h4>
          <div className="ac-chip-row">{a.users.map(u => <span key={u} className="chip kc-chip mono">{u}</span>)}</div>
        </div>

        <div className="ac-section">
          <h4><Globe2 size={13} /> Source IPs & countries</h4>
          <div className="ac-chip-row">
            {a.ips.map(ip => <span key={ip} className="chip kc-chip mono">{ip}</span>)}
          </div>
          {a.countries.length > 0 && <p className="kc-muted">{a.countries.join(', ')}</p>}
        </div>

        <div className="ac-section">
          <h4><Link2 size={13} /> Proven by</h4>
          <ul className="ac-evidence">
            {a.evidence.map(e => (
              <li key={`${e.user}|${e.ip}|${e.kind}`}>
                <span className="ac-ev-kind">{e.kind.replace('_', ' ')}</span>
                {e.user} from <span className="mono">{e.ip}</span> × {e.events.toLocaleString()}
              </li>
            ))}
            {a.accounts_created.map(c => (
              <li key={c.account}><span className="ac-ev-kind">account created</span>{c.creator} created <span className="mono">{c.account}</span></li>
            ))}
          </ul>
        </div>

        {a.incident_ids.length > 0 && (
          <div className="ac-section">
            <h4><Siren size={13} /> Linked incidents</h4>
            <div className="ac-chip-row">{a.incident_ids.map(i => <span key={i} className="chip kc-chip mono">#{i}</span>)}</div>
          </div>
        )}
      </div>
    </div>
  )
}

export default function Actors() {
  const [actors, setActors] = useState([])
  const { generation } = useRun()
  const [error, setError] = useState('')
  const [open, setOpen] = useState(null)

  useEffect(() => { getActors().then(setActors).catch(e => setError(String(e))) }, [generation])

  return (
    <div className="kc-page">
      <div className="card kc-note">
        <Fingerprint size={16} className="an-note-icon" />
        <div>
          One actor across IPs and accounts, linked only by successful logins, configuration
          changes and account creation. Failed logins never link anything. Click a profile for details.
        </div>
      </div>
      {error && <div className="kc-error">{error}</div>}
      {actors.length === 0 ? (
        <div className="card kc-empty-state"><User size={24} /><b>No linked actors yet</b></div>
      ) : (
        <div className="ac-grid">
          {actors.map(a => <ActorCard key={a.actor_id} a={a} onOpen={setOpen} />)}
        </div>
      )}
      {open && <ActorModal a={open} onClose={() => setOpen(null)} />}
    </div>
  )
}
