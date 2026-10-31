import { useEffect, useState } from 'react'
import { ChevronLeft, ChevronRight, Radar, Search, TrendingDown, TrendingUp } from 'lucide-react'
import { getAnomalies } from '../api'

const PAGE_SIZE = 40
const KINDS = [
  { id: '', label: 'All' },
  { id: 'internal_host', label: 'Internal host' },
  { id: 'external_ip', label: 'External IP' },
  { id: 'user', label: 'User' },
]
const KIND_LABEL = { internal_host: 'Internal host', external_ip: 'External IP', user: 'User' }

function scoreTier(score) {
  if (score >= 90) return 'bad'
  if (score >= 70) return 'warn'
  return 'plain'
}

function Reason({ text }) {
  const above = text.includes('above the peer median')
  const Icon = above ? TrendingUp : TrendingDown
  return <div className={`an-reason${above ? ' up' : ' down'}`}><Icon size={12} /> {text}</div>
}

export default function Anomalies() {
  const [data, setData] = useState({ total: 0, all_total: 0, items: [] })
  const [offset, setOffset] = useState(0)
  const [kind, setKind] = useState('')
  const [q, setQ] = useState('')
  const [showQuiet, setShowQuiet] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    getAnomalies({ limit: PAGE_SIZE, offset, kind, q, notable_only: !showQuiet })
      .then(setData).catch(e => setError(String(e)))
  }, [offset, kind, q, showQuiet])

  useEffect(() => { setOffset(0) }, [kind, q, showQuiet])

  const last = Math.min(offset + PAGE_SIZE, data.total)
  const hidden = data.all_total - (showQuiet ? data.all_total : data.total)

  return (
    <div className="kc-page">
      <div className="card kc-note an-note">
        <Radar size={16} className="an-note-icon" />
        <div>
          Internal hosts and users scoring above 50, and external IPs above 80, that are in no
          incident. These are leads to look at, not confirmed attacks, and they never appear on
          the incident board.
          {!showQuiet && hidden > 0 && (
            <> <b>{hidden.toLocaleString()}</b> more score high only because they are unusually
              <i> quiet</i> (far below their peer's normal traffic) — not a sign of an attack, so
              they are hidden by default.</>
          )}
        </div>
      </div>

      <div className="an-toolbar">
        <div className="an-kinds">
          {KINDS.map(k => (
            <button key={k.id} className={kind === k.id ? 'on' : ''} onClick={() => setKind(k.id)}>{k.label}</button>
          ))}
        </div>
        <div className="an-search">
          <Search size={13} />
          <input value={q} onChange={e => setQ(e.target.value)} placeholder="Filter by IP, host or user" />
        </div>
        <label className="an-quiet-toggle">
          <input type="checkbox" checked={showQuiet} onChange={e => setShowQuiet(e.target.checked)} />
          Also show quiet entities
        </label>
      </div>

      {error && <div className="kc-error">{error}</div>}

      {data.items.length === 0 ? (
        <div className="card kc-empty-state">
          <Radar size={24} />
          <b>No matching leads</b>
          <span>Try a different filter, or show quiet entities too.</span>
        </div>
      ) : (
        <div className="an-list">
          {data.items.map(a => (
            <article key={`${a.kind}:${a.entity}`} className="card an-card">
              <div className="an-card-top">
                <span className={`an-score tone-${scoreTier(a.score)}`}>{a.score.toFixed(1)}</span>
                <span className="mono an-entity">{a.entity}</span>
                <span className="chip kc-chip">{KIND_LABEL[a.kind] || a.kind}</span>
              </div>
              <div className="an-reasons">{a.reasons.map(r => <Reason key={r} text={r} />)}</div>
            </article>
          ))}
        </div>
      )}

      <div className="kc-actions">
        <span className="kc-muted">
          {data.total ? `${(offset + 1).toLocaleString()}–${last.toLocaleString()} of ${data.total.toLocaleString()}` : 'No anomaly leads'}
        </span>
        <button className="btn-ghost" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>
          <ChevronLeft size={13} /> Previous
        </button>
        <button className="btn-ghost" disabled={last >= data.total} onClick={() => setOffset(offset + PAGE_SIZE)}>
          Next <ChevronRight size={13} />
        </button>
      </div>
    </div>
  )
}
