import { useState } from 'react'
import { Gavel, Loader2, Scale, ShieldQuestion, Sparkles } from 'lucide-react'
import { getIncidentReview } from '../../api'
import { prettifyText } from './format'

const SOURCE = { llm: 'live LLM', cached: 'saved LLM answer', template: 'built-in template' }
const TONE = { critical: 'bad', high: 'warn', medium: 'info', low: 'plain' }

function Side({ icon: Icon, title, help, items, onCite, tone }) {
  return (
    <section className={`card kc-side tone-${tone}`}>
      <header><Icon size={18} /><div><h4>{title}</h4><span className="kc-muted">{help}</span></div></header>
      <ul>
        {items.map((a, i) => (
          <li key={i}>
            <p>{prettifyText(a.text)}</p>
            <div>
              {a.evidence.map(id => (
                <button key={id} className="kc-cite mono" onClick={() => onCite(id)} title="Show this evidence">{id}</button>
              ))}
            </div>
          </li>
        ))}
        {items.length === 0 && <li className="kc-muted">No arguments on this side.</li>}
      </ul>
    </section>
  )
}

export default function ReviewTab({ incidentId, review, onReview }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [cited, setCited] = useState(null)

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
  const v = review.verdict
  return (
    <div className="kc-tab-page">
      <div className="kc-tab-intro kc-intro-row">
        <div>
          <h3>Prosecutor vs Devil's Advocate</h3>
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

      <section className={`card kc-verdict tone-${TONE[v.final_priority] || 'plain'}`}>
        <Gavel size={22} />
        <div>
          <div className="kc-panel-kicker">Verdict</div>
          <h4>{v.final_priority} priority{v.lowered ? ` (lowered from ${v.risk_level})` : ''}</h4>
          <p>{v.reason} The incident stays on the board either way.</p>
          <span className="kc-muted">Computed by a fixed rule, not by the LLM. Arguments written by: {SOURCE[review.generated_by] || review.generated_by}{review.note ? ` (${review.note.replace(/\.$/, '')})` : ''}.</span>
        </div>
      </section>

      <div className="kc-sides">
        <Side icon={Scale} title="Prosecutor" help="Why this is a real attack" tone="bad" items={review.prosecution} onCite={cite} />
        <Side icon={ShieldQuestion} title="Devil's Advocate" help="What could explain it innocently" tone="info" items={review.defence} onCite={cite} />
      </div>

      {v.verify.length > 0 && (
        <section className="card kc-block">
          <h4>What to check to settle it</h4>
          <ul className="kc-checks">{v.verify.map(q => <li key={q}>{q}</li>)}</ul>
        </section>
      )}

      <section className="card kc-block">
        <h4>Evidence</h4>
        <ol className="kc-evidence">
          {review.evidence.map(e => (
            <li key={e.id} id={`kc-ev-${e.id}`} className={cited === e.id ? 'on' : ''}>
              <span className="kc-cite mono">{e.id}</span>
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
