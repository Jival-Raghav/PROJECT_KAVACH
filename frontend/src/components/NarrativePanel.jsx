import { Fragment, useEffect, useRef, useState } from 'react'
import { streamNarrative, streamInference, postFeedback } from '../api'
import {
  BrainCircuit, Scale, AlertOctagon, Loader2, RefreshCw, Gavel,
  CheckCircle2, ListChecks, ShieldAlert, Sparkles,
} from 'lucide-react'

/* ── Style maps ────────────────────────────────────── */

const SEVERITY_BG = {
  CRITICAL:      'badge-critical',
  HIGH:          'badge-critical',
  REVIEW:        'badge-review',
  INFORMATIONAL: 'badge-neutral',
  SUPPRESSED:    'badge-neutral',
}

const ACTION_BG = {
  ESCALATE:    'badge-critical',
  INVESTIGATE: 'badge-review',
  MONITOR:     'badge-review',
  DISMISS:     'badge-normal',
}

const CONFIDENCE_COLOR = {
  HIGH:   'var(--c-critical)',
  MEDIUM: 'var(--c-review)',
  LOW:    'var(--text-muted)',
}

/* ── Prose helpers ─────────────────────────────────── */

// LLMs love narrow no-break spaces and non-breaking hyphens; normalise so text wraps.
const tidy = s => s.replace(/[  ]/g, ' ').replace(/‑/g, '-').replace(/\s+/g, ' ').trim()

// Ticket ids, IPs/CIDRs, clock times, and Resource_Names get a mono chip.
const ENTITY = /([A-Z]{2,}-\d{4}-\d+|\b\d{1,3}(?:\.\d{1,3}){3}(?:\/\d+)?|\b\d{1,2}:\d{2}(?:\s?[AP]M)?|\b[A-Z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)+\b)/g

function Highlighted({ text }) {
  return text.split(ENTITY).map((part, i) =>
    i % 2 === 1 ? <code key={i} className="np-entity">{part}</code> : <Fragment key={i}>{part}</Fragment>
  )
}

// Lead sentence + body paragraphs of ~2 sentences, so a wall of text becomes scannable.
function toBlocks(raw) {
  const text = tidy(raw || '')
  if (!text) return { lead: '', paras: [] }
  const sentences = text.split(/(?<=[.!?])\s+(?=[A-Z("])/)
  const [lead, ...rest] = sentences
  const paras = []
  for (let i = 0; i < rest.length; i += 2) paras.push(rest.slice(i, i + 2).join(' '))
  return { lead, paras }
}

function Prose({ text, streaming }) {
  const { lead, paras } = toBlocks(text)
  return (
    <div className={`np-prose${streaming ? ' cursor' : ''}`}>
      <p className="np-lead"><Highlighted text={lead} /></p>
      {paras.map((p, i) => <p key={i} className="np-para"><Highlighted text={p} /></p>)}
    </div>
  )
}

function tryParseInference(raw) {
  const cleaned = raw.replace(/```(?:json)?\s*/g, '').replace(/```/g, '').trim()
  const start = cleaned.indexOf('{')
  const end   = cleaned.lastIndexOf('}')
  if (start === -1 || end === -1) return null
  try { return JSON.parse(cleaned.slice(start, end + 1)) } catch { return null }
}

/* ── Component ─────────────────────────────────────── */

export default function NarrativePanel({ user }) {
  const [prosecution, setProsecution]  = useState('')
  const [da,          setDa]           = useState('')
  const [activeSection, setSection]    = useState(null)
  const [streaming,   setStreaming]     = useState(false)
  const [done,        setDone]         = useState(false)
  const [error,       setError]        = useState(null)
  const [narrative,   setNarrative]    = useState(null)
  const [tab,         setTab]          = useState('prosecutor')

  const [inferencing,     setInferencing]    = useState(false)
  const [inferenceRaw,    setInferenceRaw]   = useState('')
  const [inferenceResult, setInferenceResult]= useState(null)
  const [inferenceError,  setInferenceError] = useState(null)

  const sourceRef    = useRef(null)
  const inferenceRef = useRef(null)

  // Streaming buffer: accumulate chunks in refs, flush via rAF so token rate
  // doesn't dictate render rate.
  const proseBuf  = useRef('')
  const daBuf     = useRef('')
  const rafHandle = useRef(null)

  const flushBuffers = () => {
    rafHandle.current = null
    const p = proseBuf.current
    const d = daBuf.current
    proseBuf.current = ''
    daBuf.current    = ''
    if (p) setProsecution(prev => prev + p)
    if (d) setDa(prev => prev + d)
  }

  const scheduleFlush = () => {
    if (!rafHandle.current) rafHandle.current = requestAnimationFrame(flushBuffers)
  }

  const start = () => {
    if (!user?.user_id) return

    if (rafHandle.current) { cancelAnimationFrame(rafHandle.current); rafHandle.current = null }
    proseBuf.current = ''
    daBuf.current    = ''

    setProsecution(''); setDa(''); setSection(null)
    setStreaming(true); setDone(false); setError(null); setNarrative(null)
    setInferenceRaw(''); setInferenceResult(null); setInferenceError(null)
    setTab('prosecutor')

    sourceRef.current?.close()
    sourceRef.current = streamNarrative(user.user_id, {
      refresh: true,
      onSection: s => { setSection(s); setTab(s) },
      onChunk:   (chunk, section) => {
        if (section === 'prosecutor') proseBuf.current += chunk
        else if (section === 'da')   daBuf.current    += chunk
        scheduleFlush()
      },
      onError: msg => { setError(msg); setStreaming(false) },
      onDone:  ()  => {
        if (rafHandle.current) { cancelAnimationFrame(rafHandle.current); rafHandle.current = null }
        flushBuffers()
        setStreaming(false); setDone(true)
      },
    })
  }

  const runInference = () => {
    if (!user?.user_id || inferencing) return
    setInferencing(true)
    setInferenceRaw('')
    setInferenceResult(null)
    setInferenceError(null)

    inferenceRef.current?.close()
    inferenceRef.current = streamInference(user.user_id, {
      onChunk: chunk => setInferenceRaw(t => t + chunk),
      onError: msg  => { setInferenceError(msg); setInferencing(false) },
      onDone:  raw  => {
        setInferenceResult(tryParseInference(raw))
        setInferencing(false)
      },
    })
  }

  useEffect(() => {
    sourceRef.current?.close()
    inferenceRef.current?.close()

    if (rafHandle.current) { cancelAnimationFrame(rafHandle.current); rafHandle.current = null }
    proseBuf.current = ''
    daBuf.current    = ''

    setProsecution(''); setDa(''); setSection(null)
    setStreaming(false); setDone(false); setError(null)
    setInferenceRaw(''); setInferenceResult(null); setInferenceError(null)
    setInferencing(false); setTab('prosecutor')

    if (user?.narrative) {
      setNarrative(user.narrative)
      setProsecution(user.narrative.prosecution || '')
      setDa(user.narrative.devils_advocate || '')
      setDone(true)
    } else {
      setNarrative(null)
    }

    return () => {
      sourceRef.current?.close()
      inferenceRef.current?.close()
      if (rafHandle.current) { cancelAnimationFrame(rafHandle.current); rafHandle.current = null }
    }
  }, [user?.user_id])

  if (!user) {
    return (
      <div className="np-empty">
        <BrainCircuit size={24} />
        <p>Select a user to generate a two-pass narrative.</p>
      </div>
    )
  }

  const cached     = narrative || user?.narrative
  const severity   = cached?.final_severity
  const doubtScore = cached?.doubt_score ?? null
  const hasText    = !!(prosecution || da)
  const canInfer   = done && hasText
  const showVerdict = tab === 'verdict'

  const segments = [
    { key: 'prosecutor', label: 'Prosecution',      icon: AlertOctagon, live: streaming && activeSection === 'prosecutor' },
    { key: 'da',         label: "Devil's advocate", icon: Scale,        live: streaming && activeSection === 'da' },
    { key: 'verdict',    label: 'Verdict',          icon: Gavel,        live: inferencing },
  ]

  return (
    <div className="np-root">

      {/* ── Summary strip ── */}
      <div className="np-summary">
        <div className="np-summary-main">
          <div className="np-summary-top">
            <span className="np-title">Narrative for {user.username}</span>
            {severity && <span className={SEVERITY_BG[severity] || 'badge-neutral'}>{severity}</span>}
          </div>
          {doubtScore !== null && (
            <div className="np-doubt" title="0 = certain threat, 1 = likely false positive">
              <span className="np-doubt-label">Doubt</span>
              <div className="doubt-track np-doubt-track"><div className="doubt-fill" style={{ width: `${doubtScore * 100}%` }} /></div>
              <span className="mono np-doubt-val">{(doubtScore * 100).toFixed(0)}%</span>
            </div>
          )}
        </div>
        <button
          id={`narrative-refresh-${user.user_id}`}
          onClick={start}
          disabled={streaming}
          className="btn-icon np-refresh"
          title="Regenerate narrative"
          aria-label="Regenerate narrative"
        >
          {streaming ? <Loader2 size={13} className="spin-slow" /> : <RefreshCw size={13} />}
        </button>
      </div>

      {/* ── Segmented control ── */}
      <div className="np-seg" role="tablist">
        {segments.map(({ key, label, icon: Icon, live }) => (
          <button
            key={key}
            id={`narrative-tab-${key}`}
            role="tab"
            aria-selected={tab === key}
            className={`np-seg-btn${tab === key ? ' active' : ''} ${key}`}
            onClick={() => setTab(key)}
          >
            <Icon size={12} />
            {label}
            {live && <span className="np-live pulse-dot" />}
          </button>
        ))}
      </div>

      {/* ── Reading pane ── */}
      <div className="np-pane">
        {error && <div className="np-alert"><ShieldAlert size={13} /> {error}</div>}

        {!showVerdict && !hasText && !streaming && (
          <div className="np-empty">
            <Sparkles size={22} />
            <p>No narrative yet. Two models will argue the case: one for the threat, one against.</p>
            <button id={`narrative-generate-${user.user_id}`} onClick={start} className="btn-primary">
              Generate narrative
            </button>
          </div>
        )}

        {!showVerdict && (hasText || streaming) && (
          <div className={`np-card ${tab}`} key={tab}>
            <div className={`np-speaker ${tab}`}>
              <span className="np-speaker-icon">
                {tab === 'prosecutor' ? <AlertOctagon size={14} /> : <Scale size={14} />}
              </span>
              <span className="np-speaker-text">
                <span className="np-speaker-role">{tab === 'prosecutor' ? 'Prosecution' : "Devil's advocate"}</span>
                <span className="np-speaker-title">{tab === 'prosecutor' ? 'The case against' : 'The case for the user'}</span>
              </span>
              {done && (tab === 'prosecutor' ? cached?.prosecutor_model : cached?.da_model) && (
                <span className="np-model">{tab === 'prosecutor' ? cached.prosecutor_model : cached.da_model}</span>
              )}
            </div>
            {(tab === 'prosecutor' ? prosecution : da)
              ? <Prose text={tab === 'prosecutor' ? prosecution : da} streaming={streaming && tab === activeSection} />
              : <p className="np-waiting">Waiting for {tab === 'prosecutor' ? 'the prosecutor' : "the devil's advocate"}…</p>}
          </div>
        )}

        {showVerdict && (
          <VerdictView
            canInfer={canInfer} inferencing={inferencing} onRun={runInference}
            raw={inferenceRaw} result={inferenceResult} error={inferenceError} userId={user.user_id}
          />
        )}
      </div>

      {/* ── Recommendation footer ── */}
      {done && cached?.recommendation && !showVerdict && (
        <div className="np-reco">
          <div className="np-reco-label">Recommendation</div>
          <div className="np-reco-text">{tidy(cached.recommendation)}</div>
        </div>
      )}
    </div>
  )
}

/* ── Verdict ───────────────────────────────────────── */

function VerdictView({ canInfer, inferencing, onRun, raw, result, error, userId }) {
  const [fpState, setFpState] = useState('idle') // idle | saving | done | failed

  const markFalsePositive = async () => {
    setFpState('saving')
    try {
      await postFeedback(userId, 'suppress', tidy(result.rationale || 'Verdict: dismiss'))
      setFpState('done')
    } catch (e) {
      console.error(e)
      setFpState('failed')
    }
  }

  if (error) return <div className="np-alert"><ShieldAlert size={13} /> Inference failed: {error}</div>

  if (!result && !inferencing && !raw) {
    return (
      <div className="np-empty">
        <Gavel size={22} />
        <p>{canInfer
          ? 'Weigh both arguments and get a final call with next steps.'
          : 'Generate the narrative first, then ask for a verdict.'}</p>
        <button id={`narrative-inference-${userId}`} onClick={onRun} disabled={!canInfer} className="btn-primary">
          Get final verdict
        </button>
      </div>
    )
  }

  if (!result) {
    return (
      <div className="np-verdict">
        <div className="np-speaker verdict"><Loader2 size={13} className="spin-slow" /><span>Weighing the evidence…</span></div>
        <pre className="np-raw">{raw || ' '}</pre>
      </div>
    )
  }

  return (
    <div className="np-verdict">
      <div className="np-verdict-head">
        <span className="np-verdict-eyebrow"><Gavel size={12} /> Final verdict</span>
        <div className="np-verdict-row">
          {result.recommended_action && (
            <span className={`${ACTION_BG[result.recommended_action] || 'badge-review'} np-action`}>{result.recommended_action}</span>
          )}
          {result.confidence && (
            <span className="np-conf">
              Confidence <strong style={{ color: CONFIDENCE_COLOR[result.confidence] || 'var(--text-secondary)' }}>{result.confidence.toLowerCase()}</strong>
            </span>
          )}
        </div>
      </div>

      {result.recommended_action === 'DISMISS' && (
        <button
          onClick={markFalsePositive}
          disabled={fpState === 'saving' || fpState === 'done'}
          className="btn-ghost"
          style={{ alignSelf: 'flex-start' }}
        >
          {fpState === 'saving' ? <Loader2 size={12} className="spin-slow" /> : <CheckCircle2 size={12} />}
          {fpState === 'done' ? 'Marked as false positive'
            : fpState === 'failed' ? 'Failed — retry marking as false positive'
            : 'Mark as false positive'}
        </button>
      )}

      {result.what_happened && (
        <section className="np-block plain">
          <h4><ShieldAlert size={12} /> What happened</h4>
          <p className="np-para"><Highlighted text={tidy(result.what_happened)} /></p>
        </section>
      )}

      {result.key_findings?.length > 0 && (
        <section className="np-block amber">
          <h4><ListChecks size={12} /> Key findings</h4>
          <ul>{result.key_findings.map((f, i) => <li key={i}><Highlighted text={tidy(f)} /></li>)}</ul>
        </section>
      )}

      {result.remediation_steps?.length > 0 && (
        <section className="np-block green">
          <h4><CheckCircle2 size={12} /> Remediation steps</h4>
          <ol>{result.remediation_steps.map((s, i) => <li key={i}><Highlighted text={tidy(s)} /></li>)}</ol>
        </section>
      )}

      {result.rationale && <blockquote className="np-rationale">{tidy(result.rationale)}</blockquote>}
    </div>
  )
}
