import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Ban, Check, ChevronRight, ClipboardCheck, Copy, FileTerminal, Globe, History, ListChecks,
  RotateCcw, ScrollText, Search, Shield, Siren, Stethoscope, Terminal, Undo2, UserX, X,
} from 'lucide-react'
import { exportResponseScript, getResponseActions, getResponseAudit, moveResponseAction } from '../api'

const NEXT = {
  proposed: [['approved', 'Approve', Check], ['rejected', 'Reject', X]],
  approved: [['rejected', 'Reject', X]],
  rejected: [['proposed', 'Reopen', Undo2]],
  exported: [],
}

// Which kinds the exporter can turn into FortiOS commands; the rest become a manual step.
const SCRIPTABLE = new Set(['block_ip', 'isolate_host', 'disable_account', 'restore_logging'])

const KIND_META = {
  block_ip: { label: 'Block external IP', icon: Ban, tone: 'bad' },
  block_domain: { label: 'Block domain', icon: Globe, tone: 'bad' },
  isolate_host: { label: 'Isolate host', icon: Shield, tone: 'warn' },
  inspect_host: { label: 'Inspect host', icon: Stethoscope, tone: 'info' },
  disable_account: { label: 'Disable account', icon: UserX, tone: 'bad' },
  remove_webshell: { label: 'Remove webshell', icon: Siren, tone: 'bad' },
  restore_logging: { label: 'Restore logging', icon: ScrollText, tone: 'warn' },
  restore_policy: { label: 'Restore policy', icon: RotateCcw, tone: 'warn' },
  review_hosts: { label: 'Review host list', icon: ListChecks, tone: 'plain' },
}
const STATUSES = [
  { id: '', label: 'All' },
  { id: 'proposed', label: 'Proposed' },
  { id: 'approved', label: 'Approved' },
  { id: 'rejected', label: 'Rejected' },
  { id: 'exported', label: 'Exported' },
]
const STATUS_TONE = { proposed: 'plain', approved: 'good', rejected: 'bad', exported: 'info' }

function ActionRow({ a, onMove, busy }) {
  const meta = KIND_META[a.kind] || { label: a.kind, icon: Terminal, tone: 'plain' }
  const scriptable = SCRIPTABLE.has(a.kind)
  return (
    <li className={`rp-row status-${a.status}`}>
      <span className={`rp-row-icon tone-${meta.tone}`}><meta.icon size={15} /></span>
      <div className="rp-row-main">
        <div className="rp-row-title">{a.title}</div>
        <div className="rp-row-why">
          {a.why}
          <span className={`rp-exec${scriptable ? ' auto' : ''}`} title={scriptable
            ? 'The export writes FortiOS commands for this action.'
            : 'No command is generated: the export lists this as a manual step.'}>
            {scriptable ? <Terminal size={11} /> : <ClipboardCheck size={11} />}
            {scriptable ? 'scripted' : 'manual step'}
          </span>
          {a.incident_ids.map(i => <span key={i} className="rp-inc mono">#{i}</span>)}
        </div>
      </div>
      <span className={`rp-status tone-${STATUS_TONE[a.status] || 'plain'}`}>{a.status}</span>
      <span className="rp-row-actions">
        {NEXT[a.status].map(([to, label, Icon]) => (
          <button key={to} className="btn-ghost" disabled={busy} onClick={() => onMove(a.action_id, to)}>
            <Icon size={12} /> {label}
          </button>
        ))}
      </span>
    </li>
  )
}

function KindGroup({ kind, items, onMove, busy }) {
  const [open, setOpen] = useState(true)
  const meta = KIND_META[kind] || { label: kind, icon: Terminal, tone: 'plain' }
  return (
    <section className="card rp-group">
      <button className="rp-group-head" onClick={() => setOpen(o => !o)} aria-expanded={open}>
        <span className={`rp-row-icon tone-${meta.tone}`}><meta.icon size={15} /></span>
        <h4>{meta.label}</h4>
        <span className="kc-count">{items.length}</span>
        <span className="kc-muted">
          {SCRIPTABLE.has(kind) ? 'exports as FortiOS commands' : 'exports as a manual step'}
        </span>
        <ChevronRight size={15} className={`rl-chevron${open ? ' open' : ''}`} />
      </button>
      {open && <ul className="rp-rows">{items.map(a => <ActionRow key={a.action_id} a={a} onMove={onMove} busy={busy} />)}</ul>}
    </section>
  )
}

export default function ResponsePlan() {
  const [actions, setActions] = useState([])
  const [audit, setAudit] = useState([])
  const [script, setScript] = useState('')
  const [copied, setCopied] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [kind, setKind] = useState('')
  const [status, setStatus] = useState('')
  const [q, setQ] = useState('')

  const load = useCallback(() => {
    getResponseActions().then(setActions).catch(e => setError(String(e)))
    getResponseAudit().then(setAudit).catch(() => {})
  }, [])

  useEffect(load, [load])

  const move = (id, to) => {
    setBusy(true)
    moveResponseAction(id, to).then(load).catch(e => setError(String(e))).finally(() => setBusy(false))
  }
  const exportNow = () => exportResponseScript().then(text => { setScript(text); setCopied(false); load() })
    .catch(e => setError(String(e)))
  const copyScript = () => navigator.clipboard?.writeText(script).then(() => setCopied(true)).catch(() => {})

  const counts = useMemo(() => actions.reduce((acc, a) => ({ ...acc, [a.status]: (acc[a.status] || 0) + 1 }), {}), [actions])
  const kinds = useMemo(() => {
    const seen = new Map()
    actions.forEach(a => seen.set(a.kind, (seen.get(a.kind) || 0) + 1))
    return [...seen.entries()].sort((a, b) => b[1] - a[1])
  }, [actions])

  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return actions.filter(a => (!kind || a.kind === kind) && (!status || a.status === status)
      && (!needle || a.title.toLowerCase().includes(needle) || a.target.toLowerCase().includes(needle)
        || a.incident_ids.some(i => `#${i}`.includes(needle))))
  }, [actions, kind, status, q])

  const grouped = useMemo(() => {
    const by = new Map()
    shown.forEach(a => by.set(a.kind, [...(by.get(a.kind) || []), a]))
    return [...by.entries()].sort((a, b) => b[1].length - a[1].length)
  }, [shown])

  const approvable = shown.filter(a => a.status === 'proposed')
  const approveShown = () => {
    setBusy(true)
    approvable.reduce((chain, a) => chain.then(() => moveResponseAction(a.action_id, 'approved').catch(() => {})),
      Promise.resolve()).then(load).finally(() => setBusy(false))
  }

  return (
    <div className="kc-page">
      <div className="card kc-note an-note">
        <Shield size={16} className="an-note-icon" />
        <div>
          Actions proposed by the incidents. <b>Kavach never touches the firewall.</b> Approved
          actions are only written out as a dry-run script for a person to read and run — and any
          value the log could not prove safe becomes a manual step instead of a command.
        </div>
      </div>

      {error && <div className="kc-error">{error}</div>}

      <div className="rp-summary">
        {STATUSES.slice(1).map(s => (
          <button
            key={s.id}
            className={`rp-tile tone-${STATUS_TONE[s.id]}${status === s.id ? ' on' : ''}`}
            onClick={() => setStatus(status === s.id ? '' : s.id)}
          >
            <b>{(counts[s.id] || 0).toLocaleString()}</b>
            <span>{s.label}</span>
          </button>
        ))}
        <div className="rp-export">
          <button className="btn-primary" onClick={exportNow} disabled={!counts.approved}>
            <FileTerminal size={14} /> Export {counts.approved || 0} approved as dry-run script
          </button>
        </div>
      </div>

      <div className="an-toolbar">
        <div className="an-kinds">
          <button className={kind === '' ? 'on' : ''} onClick={() => setKind('')}>All kinds</button>
          {kinds.map(([k, n]) => (
            <button key={k} className={kind === k ? 'on' : ''} onClick={() => setKind(k)}>
              {(KIND_META[k] || {}).label || k} <span className="rp-pill-n">{n}</span>
            </button>
          ))}
        </div>
        <div className="an-search">
          <Search size={13} />
          <input value={q} onChange={e => setQ(e.target.value)} placeholder="Filter by IP, account, domain or #incident" />
        </div>
        {approvable.length > 0 && (
          <button className="btn-ghost rp-bulk" disabled={busy} onClick={approveShown}>
            <Check size={13} /> Approve all {approvable.length} shown
          </button>
        )}
      </div>

      {script && (
        <section className="card rp-script">
          <div className="rp-script-head">
            <h3><Terminal size={14} /> Dry-run script</h3>
            <button className="btn-ghost" onClick={copyScript}>
              <Copy size={13} /> {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
          <pre className="rl-code">{script}</pre>
        </section>
      )}

      {shown.length === 0 ? (
        <div className="card kc-empty-state">
          <ListChecks size={24} />
          <b>No matching actions</b>
          <span>Try a different kind, status or search.</span>
        </div>
      ) : (
        <div className="rp-groups">
          {grouped.map(([k, items]) => (
            <KindGroup key={k} kind={k} items={items} onMove={move} busy={busy} />
          ))}
        </div>
      )}

      {audit.length > 0 && (
        <section className="card kc-block">
          <div className="kc-block-head"><History size={15} /><h4>Audit trail</h4>
            <span className="kc-count">{audit.length}</span>
          </div>
          <ol className="rp-audit">
            {[...audit].reverse().slice(0, 30).map((e, i) => (
              <li key={i}>
                <span className="mono kc-muted">{e.timestamp.replace('T', ' ').slice(0, 19)}</span>
                <span className="rp-audit-actor">{e.actor}</span>
                <span className="mono rp-audit-id">{e.action_id}</span>
                <span className={`rp-status tone-${STATUS_TONE[e.to] || 'plain'}`}>{e.from} → {e.to}</span>
              </li>
            ))}
          </ol>
        </section>
      )}
    </div>
  )
}
