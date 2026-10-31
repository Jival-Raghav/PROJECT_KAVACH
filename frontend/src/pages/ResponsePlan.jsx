import { useEffect, useMemo, useState } from 'react'
import {
  Ban, ChevronRight, Globe, ListChecks, RotateCcw, ScrollText, Search, Shield, Siren,
  Stethoscope, Terminal, TriangleAlert, UserX, Wrench,
} from 'lucide-react'
import { getResponseActions } from '../api'

// Kinds the firewall itself can carry out; the rest are legwork for a person.
const FIREWALL_CHANGE = new Set(['block_ip', 'isolate_host', 'disable_account', 'restore_logging'])

const KIND_META = {
  block_ip: {
    label: 'Block external IP', icon: Ban, tone: 'bad',
    what: 'Add the address to a blocklist group so the firewall drops its traffic.',
    check: 'Check the address is not a shared exit point such as a customer NAT, a partner VPN or a CDN node. Blocking one of those cuts off legitimate users as well.',
  },
  block_domain: {
    label: 'Block domain', icon: Globe, tone: 'bad',
    what: 'Stop the firewall resolving or reaching this domain name.',
    check: 'Confirm nothing legitimate depends on the domain first. A name can also be reached by its address, so blocking the name alone is not the whole job.',
  },
  isolate_host: {
    label: 'Isolate host', icon: Shield, tone: 'warn',
    what: 'Put the internal host in an isolation group so policy stops it reaching the rest of the network.',
    check: 'This takes the machine off the network. Tell its owner, and keep a way in for whoever has to examine it.',
  },
  inspect_host: {
    label: 'Inspect host', icon: Stethoscope, tone: 'info',
    what: 'A person examines the machine for signs of compromise. Nothing is changed automatically.',
    check: 'Start with what ran around the times in the incident timeline, and with anything new the host began talking to afterwards.',
  },
  disable_account: {
    label: 'Disable account', icon: UserX, tone: 'bad',
    what: 'Disable the local account and reset its credentials.',
    check: 'Make sure this is not the account a running service signs in with. Disabling one of those stops the service too.',
  },
  remove_webshell: {
    label: 'Remove webshell', icon: Siren, tone: 'bad',
    what: 'A person finds and deletes the planted file on the web server, then works out how it got there.',
    check: 'Keep a copy before deleting it. Removing the file does not close the hole that let it be written.',
  },
  restore_logging: {
    label: 'Restore logging', icon: ScrollText, tone: 'warn',
    what: 'Turn firewall disk logging back on and confirm it is really recording.',
    check: 'Logging was changed during this incident, so treat the quiet stretch in the log as a blind spot rather than as nothing happening.',
  },
  restore_policy: {
    label: 'Restore policy', icon: RotateCcw, tone: 'warn',
    what: 'Restore the firewall policy set from a known-good backup.',
    check: 'Compare the backup against the current policy first, so restoring it does not undo legitimate changes made since.',
  },
  review_hosts: {
    label: 'Review host list', icon: ListChecks, tone: 'plain',
    what: 'Too many hosts took part to list one by one. Query the log for this incident’s full host list.',
    check: 'The number in the title is a floor, not a total: a detection stores at most 50 entities per role.',
  },
}
const FALLBACK = { label: 'Action', icon: Terminal, tone: 'plain', what: '', check: '' }

function ActionRow({ a }) {
  const [open, setOpen] = useState(false)
  const meta = KIND_META[a.kind] || FALLBACK
  const byFirewall = FIREWALL_CHANGE.has(a.kind)
  return (
    <li className="rp-row">
      <button className="rp-row-top" onClick={() => setOpen(o => !o)} aria-expanded={open}>
        <span className={`rp-row-icon tone-${meta.tone}`}><meta.icon size={15} /></span>
        <span className="rp-row-main">
          <span className="rp-row-title">{a.title}</span>
          <span className="rp-row-why">{a.why}</span>
        </span>
        <span className={`rp-exec${byFirewall ? ' auto' : ''}`}>
          {byFirewall ? <Wrench size={11} /> : <Stethoscope size={11} />}
          {byFirewall ? 'firewall change' : 'needs a person'}
        </span>
        <span className="rp-incs">{a.incident_ids.map(i => <span key={i} className="rp-inc mono">#{i}</span>)}</span>
        <ChevronRight size={15} className={`rl-chevron${open ? ' open' : ''}`} />
      </button>
      {open && (
        <div className="rp-detail">
          <dl className="rp-facts">
            <div><dt>What this means</dt><dd>{meta.what}</dd></div>
            <div><dt>Why it is here</dt><dd>{a.why}</dd></div>
            <div><dt>Target</dt><dd className="mono">{a.target}</dd></div>
            <div>
              <dt>From</dt>
              <dd>{a.incident_ids.length === 1 ? 'Incident ' : 'Incidents '}
                {a.incident_ids.map(i => `#${i}`).join(', ')}</dd>
            </div>
            <div>
              <dt>Carried out by</dt>
              <dd>{byFirewall
                ? 'A change on the firewall itself.'
                : 'A person. The firewall cannot do this one.'}</dd>
            </div>
          </dl>
          {meta.check && (
            <p className="rp-check"><TriangleAlert size={13} /> <span>{meta.check}</span></p>
          )}
        </div>
      )}
    </li>
  )
}

function KindGroup({ kind, items }) {
  const [open, setOpen] = useState(true)
  const meta = KIND_META[kind] || FALLBACK
  return (
    <section className="card rp-group">
      <button className="rp-group-head" onClick={() => setOpen(o => !o)} aria-expanded={open}>
        <span className={`rp-row-icon tone-${meta.tone}`}><meta.icon size={15} /></span>
        <h4>{meta.label}</h4>
        <span className="kc-count">{items.length}</span>
        <span className="kc-muted">{meta.what}</span>
        <ChevronRight size={15} className={`rl-chevron${open ? ' open' : ''}`} />
      </button>
      {open && <ul className="rp-rows">{items.map(a => <ActionRow key={a.action_id} a={a} />)}</ul>}
    </section>
  )
}

export default function ResponsePlan() {
  const [actions, setActions] = useState([])
  const [error, setError] = useState('')
  const [kind, setKind] = useState('')
  const [q, setQ] = useState('')

  useEffect(() => { getResponseActions().then(setActions).catch(e => setError(String(e))) }, [])

  const kinds = useMemo(() => {
    const seen = new Map()
    actions.forEach(a => seen.set(a.kind, (seen.get(a.kind) || 0) + 1))
    return [...seen.entries()].sort((a, b) => b[1] - a[1])
  }, [actions])

  const stats = useMemo(() => ({
    total: actions.length,
    firewall: actions.filter(a => FIREWALL_CHANGE.has(a.kind)).length,
    people: actions.filter(a => !FIREWALL_CHANGE.has(a.kind)).length,
    incidents: new Set(actions.flatMap(a => a.incident_ids)).size,
  }), [actions])

  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return actions.filter(a => (!kind || a.kind === kind)
      && (!needle || a.title.toLowerCase().includes(needle) || a.target.toLowerCase().includes(needle)
        || a.incident_ids.some(i => `#${i}`.includes(needle))))
  }, [actions, kind, q])

  const grouped = useMemo(() => {
    const by = new Map()
    shown.forEach(a => by.set(a.kind, [...(by.get(a.kind) || []), a]))
    return [...by.entries()].sort((a, b) => b[1].length - a[1].length)
  }, [shown])

  return (
    <div className="kc-page">
      <div className="card kc-note an-note">
        <Shield size={16} className="an-note-icon" />
        <div>
          What the incidents say should be done, grouped by kind. <b>Kavach never changes the
          firewall and nothing here is carried out</b> — this is a plan for a person to read, decide
          on and run themselves. Click any action to see what it means and what to check first.
        </div>
      </div>

      {error && <div className="kc-error">{error}</div>}

      <div className="rp-summary">
        <div className="rp-stat"><b>{stats.total}</b><span>proposed actions</span></div>
        <div className="rp-stat"><b>{stats.incidents}</b><span>incidents they come from</span></div>
        <div className="rp-stat"><b>{stats.firewall}</b><span>are firewall changes</span></div>
        <div className="rp-stat"><b>{stats.people}</b><span>need a person</span></div>
      </div>

      <div className="an-toolbar">
        <div className="an-kinds">
          <button className={kind === '' ? 'on' : ''} onClick={() => setKind('')}>All kinds</button>
          {kinds.map(([k, n]) => (
            <button key={k} className={kind === k ? 'on' : ''} onClick={() => setKind(k)}>
              {(KIND_META[k] || FALLBACK).label} <span className="rp-pill-n">{n}</span>
            </button>
          ))}
        </div>
        <div className="an-search">
          <Search size={13} />
          <input value={q} onChange={e => setQ(e.target.value)} placeholder="Filter by IP, account, domain or #incident" />
        </div>
      </div>

      {shown.length === 0 ? (
        <div className="card kc-empty-state">
          <ListChecks size={24} />
          <b>No matching actions</b>
          <span>Try a different kind or search.</span>
        </div>
      ) : (
        <div className="rp-groups">
          {grouped.map(([k, items]) => <KindGroup key={k} kind={k} items={items} />)}
        </div>
      )}
    </div>
  )
}
