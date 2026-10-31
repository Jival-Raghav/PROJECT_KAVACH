import { useState } from 'react'
import { Gavel, Loader2, Scale, ShieldQuestion, Sparkles } from 'lucide-react'
import { getIncidentReview } from '../../api'
import { prettifyText } from './format'

const SOURCE = { llm: 'live LLM', cached: 'saved LLM answer', template: 'built-in template' }
const TONE = { critical: 'bad', high: 'warn', medium: 'info', low: 'good' }

const VOICES = [
  {
    id: 'prosecution', label: 'Prosecution', icon: Scale, tone: 'prosecutor',
    role: 'Prosecution', title: 'The case for an attack',
    empty: 'No argument could be built for an attack.',
  },
  {
    id: 'defence', label: "Devil's advocate", icon: ShieldQuestion, tone: 'da',
    role: "Devil's advocate", title: 'The case for an innocent explanation',
    empty: 'The log offers no innocent explanation.',
  },
  { id: 'verdict', label: 'Verdict', icon: Gavel, tone: 'verdict' },
]

function Cites({ ids, onCite }) {
  if (!ids?.length) return null
  return (
    <span className="rv-cites">
      {ids.map(id => (
        <button key={id} className="rv-cite mono" onClick={() => onCite(id)} title="Show this evidence">{id}</button>
      ))}
    </span>
  )
}

function Argument({ voice, items, onCite }) {
  const [lead, ...rest] = items
  return (
    <article className={`rv-card ${voice.tone}`}>
      <header className="rv-speaker">
        <span className="rv-speaker-icon"><voice.icon size={16} /></span>
        <span className="rv-speaker-text">
          <span className="rv-speaker-role">{voice.role}</span>
          <span className="rv-speaker-title">{voice.title}</span>
        </span>
      </header>
      <div className="rv-prose">
        {lead ? (
          <p className="rv-lead">{prettifyText(lead.text)} <Cites ids={lead.evidence} onCite={onCite} /></p>
        ) : (
          <p className="rv-lead rv-muted">{voice.empty}</p>
        )}
        {rest.map((a, i) => (
          <p className="rv-para" key={i}>{prettifyText(a.text)} <Cites ids={a.evidence} onCite={onCite} /></p>
        ))}
      </div>
    </article>
  )
}

function Verdict({ review }) {
  const v = review.verdict
  return (
    <div className="rv-verdict">
      <article className={`rv-card verdict tone-${TONE[v.final_priority] || 'plain'}`}>
        <header className="rv-speaker">
          <span className="rv-speaker-icon"><Gavel size={16} /></span>
          <span className="rv-speaker-text">
            <span className="rv-speaker-role">Verdict</span>
            <span className="rv-speaker-title">Fixed rule, not the LLM</span>
          </span>
          <span className="rv-priority">{v.final_priority} priority</span>
        </header>
        <div className="rv-prose">
          <p className="rv-lead">
            {v.lowered ? `Lowered from ${v.risk_level} to ${v.final_priority}.` : `Stays at ${v.final_priority}.`} {v.reason}
          </p>
          <p className="rv-para">The incident stays on the board either way — a review never removes it.</p>
        </div>
      </article>

      {v.verify.length > 0 && (
        <section className="rv-block amber">
          <h4>What to check to settle it</h4>
          <ol>{v.verify.map(q => <li key={q}>{q}</li>)}</ol>
        </section>
      )}

      <p className="rv-foot">
        Arguments written by {SOURCE[review.generated_by] || review.generated_by}
        {review.note ? ` (${review.note.replace(/\.$/, '')})` : ''}.
      </p>
    </div>
  )
}

export default function ReviewTab({ incidentId, review, onReview }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [cited, setCited] = useState(null)
  const [pane, setPane] = useState('prosecution')

  const runLive = () => {
    setBusy(true)
    setError('')
    getIncidentReview(incidentId, true).then(onReview).catch(e => setError(String(e)))
      .finally(() => setBusy(false))
  }
  const cite = id => {
    setCited(id)
    document.getElementById(`kc-ev-${id}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' })
  }

  if (!review) return <div className="card kc-empty-state"><b>No review for this incident</b></div>
  const voice = VOICES.find(x => x.id === pane)

  return (
    <div className="kc-tab-page">
      <div className="kc-tab-intro kc-intro-row">
        <div>
          <h3>Prosecution vs Devil's Advocate</h3>
          <p>One side argues this is a real attack, the other looks for an innocent explanation. Both must cite the numbered evidence below.</p>
        </div>
        <button className="btn-ghost" onClick={runLive} disabled={busy}>
          {busy ? <Loader2 size={13} className="spin-slow" /> : <Sparkles size={13} />} Run live review
        </button>
      </div>

      {error && <div className="kc-error">{error}</div>}
      {review.injection_flags?.length > 0 && (
        <div className="kc-error">Suspected prompt injection redacted in {review.injection_flags.join(', ')}.</div>
      )}

      <div className="rv-seg" role="tablist" aria-label="Review sides">
        {VOICES.map(v => (
          <button
            key={v.id} role="tab" aria-selected={pane === v.id}
            className={`rv-seg-btn ${v.tone}${pane === v.id ? ' active' : ''}`}
            onClick={() => setPane(v.id)}
          >
            <v.icon size={14} /> {v.label}
          </button>
        ))}
      </div>

      {pane === 'verdict'
        ? <Verdict review={review} />
        : <Argument voice={voice} items={review[pane] || []} onCite={cite} />}

      <section className="card kc-block">
        <h4>Evidence</h4>
        <ol className="kc-evidence">
          {review.evidence.map(e => (
            <li key={e.id} id={`kc-ev-${e.id}`} className={cited === e.id ? 'on' : ''}>
              <span className="rv-cite mono">{e.id}</span>
              <div>
                <span className="kc-muted">{e.kind}{e.flagged ? ' · flagged, text redacted' : ''}</span>
                <p>{prettifyText(e.text)}</p>
              </div>
            </li>
          ))}
        </ol>
      </section>
    </div>
  )
}
