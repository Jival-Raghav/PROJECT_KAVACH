import { useEffect, useMemo, useState } from 'react'
import {
  Bot, KeyRound, Search, ServerCog, ShieldAlert, ShieldCheck, Siren, Settings2, Users, User,
} from 'lucide-react'
import { getAccounts, getLlmSafety } from '../api'
import { useRun } from '../run'

const TYPES = [
  { id: '', label: 'All' },
  { id: 'person', label: 'Person' },
  { id: 'service', label: 'Service' },
  { id: 'shared', label: 'Shared' },
]
const TYPE_META = {
  person: { icon: User, label: 'Person', help: 'A named human account.' },
  service: { icon: ServerCog, label: 'Service', help: 'The name looks like an automated account. A service account should never log in interactively.' },
  shared: { icon: Users, label: 'Shared', help: 'The name suggests more than one person uses it, so activity cannot be tied to an individual.' },
}
const SEV_RANK = { critical: 3, high: 2, medium: 1, low: 0 }
const SEV_TONE = { critical: 'bad', high: 'warn', medium: 'info' }

function worstSeverity(findings) {
  return findings.reduce((w, f) => (SEV_RANK[f.severity] > SEV_RANK[w] ? f.severity : w), 'low')
}

function LlmSafety({ safety }) {
  const hit = safety.incidents_with_suspected_injection
  const clean = hit.length === 0
  return (
    <section className={`card ls-banner${clean ? ' clean' : ' hit'}`}>
      <span className="ls-shield">{clean ? <ShieldCheck size={22} /> : <ShieldAlert size={22} />}</span>
      <div className="ls-body">
        <div className="ls-head">
          <h3>LLM safety</h3>
          <span className={`ls-verdict${clean ? '' : ' hit'}`}>
            {clean ? 'No prompt injection found' : `Injection redacted in ${hit.length} incident${hit.length > 1 ? 's' : ''}`}
          </span>
        </div>
        <div className="ls-stats">
          <div className="ls-stat">
            <b>{safety.evidence_items_scanned.toLocaleString()}</b>
            <span>evidence items scanned</span>
          </div>
          <div className="ls-stat">
            <b>{safety.incidents_scanned.toLocaleString()}</b>
            <span>incidents scanned</span>
          </div>
          <div className={`ls-stat${clean ? '' : ' bad'}`}>
            <b>{hit.length}</b>
            <span>with suspected injection</span>
          </div>
        </div>
        {!clean && (
          <div className="ls-hits">
            {hit.map(i => <span key={i} className="chip kc-chip mono">#{i}</span>)}
          </div>
        )}
        <p className="ls-note">
          Every piece of log text is scanned for prompt injection before any LLM can see it. Attack
          verdicts are computed by a fixed rule, so neither log text nor an LLM answer can change them.
        </p>
      </div>
    </section>
  )
}

function AccountCard({ r }) {
  const meta = TYPE_META[r.type] || { icon: KeyRound, label: r.type, help: '' }
  const Icon = meta.icon
  const worst = r.findings.length ? worstSeverity(r.findings) : null
  const stats = [
    { icon: KeyRound, value: r.vpn_logins, label: 'VPN logins' },
    { icon: ShieldAlert, value: r.admin_logins, label: 'admin logins', hot: r.admin_logins > 0 },
    { icon: Settings2, value: r.config_changes, label: 'config changes', hot: r.config_changes > 0 },
  ]
  return (
    <article className={`card acc-card${worst ? ` flag-${SEV_TONE[worst] || 'plain'}` : ''}`}>
      <header className="acc-top">
        <span className="acc-icon" title={meta.help}><Icon size={16} /></span>
        <span className="mono acc-name">{r.account}</span>
        <span className="acc-type" title={meta.help}>{meta.label}</span>
        {r.incident_ids.length > 0 && (
          <span className="acc-incidents"><Siren size={12} /> {r.incident_ids.map(i => `#${i}`).join(' ')}</span>
        )}
      </header>

      <div className="acc-stats">
        {stats.map(s => (
          <span key={s.label} className={`acc-stat${s.hot ? ' hot' : ''}`}>
            <s.icon size={12} /> <b>{s.value.toLocaleString()}</b> {s.label}
          </span>
        ))}
        {r.ips.map(ip => <span key={ip} className="acc-ip mono">{ip}</span>)}
      </div>

      {r.findings.length > 0 && (
        <ul className="acc-findings">
          {r.findings.map(f => (
            <li key={f.code} className={`tone-${SEV_TONE[f.severity] || 'plain'}`}>
              <span className="acc-sev">{f.severity}</span>
              <span>{f.text}</span>
            </li>
          ))}
        </ul>
      )}
    </article>
  )
}

export default function Accounts() {
  const [rows, setRows] = useState([])
  const { generation } = useRun()
  const [safety, setSafety] = useState(null)
  const [type, setType] = useState('')
  const [q, setQ] = useState('')
  const [flaggedOnly, setFlaggedOnly] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    getAccounts().then(setRows).catch(e => setError(String(e)))
    getLlmSafety().then(setSafety).catch(() => {})
  }, [generation])

  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return rows.filter(r => (!type || r.type === type)
      && (!flaggedOnly || r.findings.length > 0)
      && (!needle || r.account.toLowerCase().includes(needle)
        || r.ips.some(ip => ip.includes(needle))))
  }, [rows, type, q, flaggedOnly])

  const flagged = rows.filter(r => r.findings.length > 0).length

  return (
    <div className="kc-page">
      <div className="card kc-note an-note">
        <Bot size={16} className="an-note-icon" />
        <div>
          Accounts proven active by a successful login or a configuration change. Names seen only in
          failed logins are guesses, not accounts, so they are not listed. Service and shared types
          are inferred from the name.
        </div>
      </div>

      {error && <div className="kc-error">{error}</div>}
      {safety && <LlmSafety safety={safety} />}

      <div className="an-toolbar">
        <div className="an-kinds">
          {TYPES.map(t => (
            <button key={t.id} className={type === t.id ? 'on' : ''} onClick={() => setType(t.id)}>{t.label}</button>
          ))}
        </div>
        <div className="an-search">
          <Search size={13} />
          <input value={q} onChange={e => setQ(e.target.value)} placeholder="Filter by account or IP" />
        </div>
        <label className="an-quiet-toggle">
          <input type="checkbox" checked={flaggedOnly} onChange={e => setFlaggedOnly(e.target.checked)} />
          Only the {flagged} with findings
        </label>
      </div>

      {shown.length === 0 ? (
        <div className="card kc-empty-state">
          <KeyRound size={24} />
          <b>No matching accounts</b>
          <span>Try a different type or search.</span>
        </div>
      ) : (
        <div className="acc-list">{shown.map(r => <AccountCard key={r.account} r={r} />)}</div>
      )}
    </div>
  )
}
