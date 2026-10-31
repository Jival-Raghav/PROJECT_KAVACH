import { useEffect, useMemo, useState } from 'react'
import { BookCheck, ChevronRight, ClipboardList, ShieldAlert, ShieldCheck, ShieldX, Siren } from 'lucide-react'
import { getCompliance } from '../api'

export const CONTROL_STATUS = { gap: 'Gap', attempted: 'Attempted, blocked', no_failure_seen: 'No failure seen' }

const STATUS_META = {
  gap: {
    label: 'Gap', tone: 'bad', icon: ShieldX,
    help: 'The log shows this control failing: something it should have stopped got through.',
  },
  attempted: {
    label: 'Attempted, blocked', tone: 'warn', icon: ShieldAlert,
    help: 'Something tested this control and the firewall stopped it. The control held, but it is being probed.',
  },
  no_failure_seen: {
    label: 'No failure seen', tone: 'good', icon: ShieldCheck,
    help: 'Nothing in this log shows the control failing. That is not proof that it works.',
  },
}
// The standard each reference belongs to, taken from the start of the reference string.
const FRAMEWORKS = [
  { id: 'NIST', match: r => r.startsWith('NIST') },
  { id: 'ISO', match: r => r.startsWith('ISO') },
  { id: 'SOC 2', match: r => r.startsWith('SOC') },
]
const frameworkOf = ref => (FRAMEWORKS.find(f => f.match(ref)) || { id: 'Other' }).id

// Kept as a table on purpose: this is the compact view embedded in an incident's Other Info tab.
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

function ControlCard({ c }) {
  const [open, setOpen] = useState(false)
  const meta = STATUS_META[c.status] || { label: c.status, tone: 'plain', icon: ShieldCheck, help: '' }
  const Icon = meta.icon
  return (
    <article className={`card cf-card tone-${meta.tone}`}>
      <button className="cf-top" onClick={() => setOpen(o => !o)} aria-expanded={open}>
        <span className="cf-icon"><Icon size={17} /></span>
        <span className="cf-title-wrap">
          <span className="cf-title">{c.title}</span>
          <span className="mono cf-id">{c.id}</span>
        </span>
        <span className="cf-refs">
          {c.refs.map(r => <span key={r} className={`cf-ref fw-${frameworkOf(r).replace(/\s/g, '')}`}>{r}</span>)}
        </span>
        <span className="cf-status">{meta.label}</span>
        <ChevronRight size={15} className={`rl-chevron${open ? ' open' : ''}`} />
      </button>
      {open && (
        <div className="cf-detail">
          <p className="kc-muted">{meta.help}</p>
          {c.failed_in.length > 0 && (
            <div className="cf-inc-row">
              <span className="cf-inc-label bad"><Siren size={12} /> Failed in</span>
              {c.failed_in.map(i => <span key={i} className="cf-inc mono bad">#{i}</span>)}
            </div>
          )}
          {c.attempted_in.length > 0 && (
            <div className="cf-inc-row">
              <span className="cf-inc-label warn"><ShieldAlert size={12} /> Tested but blocked in</span>
              {c.attempted_in.map(i => <span key={i} className="cf-inc mono warn">#{i}</span>)}
            </div>
          )}
          {c.failed_in.length === 0 && c.attempted_in.length === 0 && (
            <p className="kc-muted">No incident in this log touched this control.</p>
          )}
        </div>
      )}
    </article>
  )
}

export default function ControlFindings() {
  const [data, setData] = useState(null)
  const [status, setStatus] = useState('')
  const [framework, setFramework] = useState('')
  const [error, setError] = useState('')

  useEffect(() => { getCompliance().then(setData).catch(e => setError(String(e))) }, [])

  const shown = useMemo(() => (data?.controls || []).filter(c =>
    (!status || c.status === status)
    && (!framework || c.refs.some(r => frameworkOf(r) === framework))), [data, status, framework])

  if (error) return <div className="kc-page"><div className="kc-error">{error}</div></div>
  if (!data) return <div className="kc-empty">Loading controls…</div>

  return (
    <div className="kc-page">
      <div className="card kc-note an-note">
        <BookCheck size={16} className="an-note-icon" />
        <div>{data.notice}</div>
      </div>

      <div className="cf-summary">
        {Object.entries(STATUS_META).map(([id, meta]) => (
          <button
            key={id}
            className={`cf-tile tone-${meta.tone}${status === id ? ' on' : ''}`}
            onClick={() => setStatus(status === id ? '' : id)}
            title={meta.help}
          >
            <meta.icon size={18} />
            <b>{data.counts[id] ?? 0}</b>
            <span>{meta.label}</span>
          </button>
        ))}
      </div>

      <div className="an-toolbar">
        <div className="an-kinds">
          <button className={framework === '' ? 'on' : ''} onClick={() => setFramework('')}>All standards</button>
          {FRAMEWORKS.map(f => (
            <button key={f.id} className={framework === f.id ? 'on' : ''} onClick={() => setFramework(f.id)}>{f.id}</button>
          ))}
        </div>
        <span className="kc-muted">{shown.length} of {data.controls.length} controls · click one to see the incidents behind it</span>
      </div>

      {shown.length === 0 ? (
        <div className="card kc-empty-state">
          <ClipboardList size={24} />
          <b>No controls match</b>
          <span>Try a different status or standard.</span>
        </div>
      ) : (
        <div className="cf-list">{shown.map(c => <ControlCard key={c.id} c={c} />)}</div>
      )}
    </div>
  )
}
