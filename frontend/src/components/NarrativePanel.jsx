import { useEffect, useRef, useState } from 'react'
import { streamNarrative, streamInference } from '../api'
import {
  BrainCircuit, MessageSquareWarning, Scale, AlertOctagon,
  Loader2, RefreshCw, Gavel, CheckCircle2, ListChecks,
  ShieldAlert, ChevronDown, ChevronUp
} from 'lucide-react'

/* ── Style maps — now using CSS variable references ─── */

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

/* ── JSON parser helper ─────────────────────────────── */

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

  // Inference state
  const [inferencing,     setInferencing]    = useState(false)
  const [inferenceRaw,    setInferenceRaw]   = useState('')
  const [inferenceResult, setInferenceResult]= useState(null)
  const [inferenceError,  setInferenceError] = useState(null)
  const [showInference,   setShowInference]  = useState(false)

  const sourceRef    = useRef(null)
  const inferenceRef = useRef(null)

  // ── Streaming buffer: accumulate chunks in refs, flush via rAF ──
  // This decouples token arrival rate from React render rate (~60fps cap)
  const proseBuf  = useRef('')   // unbatched prosecution text
  const daBuf     = useRef('')   // unbatched da text
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
    if (!rafHandle.current) {
      rafHandle.current = requestAnimationFrame(flushBuffers)
    }
  }

  const start = () => {
    if (!user?.user_id) return

    // Cancel any pending flush
    if (rafHandle.current) { cancelAnimationFrame(rafHandle.current); rafHandle.current = null }
    proseBuf.current = ''
    daBuf.current    = ''

    setProsecution(''); setDa(''); setSection(null)
    setStreaming(true); setDone(false); setError(null); setNarrative(null)
    setInferenceRaw(''); setInferenceResult(null); setInferenceError(null); setShowInference(false)

    sourceRef.current?.close()
    sourceRef.current = streamNarrative(user.user_id, {
      onSection: s => { setSection(s); setTab(s) },
      onChunk:   (chunk, section) => {
        // Append to the correct buffer and schedule a rAF flush
        if (section === 'prosecutor') proseBuf.current += chunk
        else if (section === 'da')   daBuf.current    += chunk
        scheduleFlush()
      },
      onError: msg => { setError(msg); setStreaming(false) },
      onDone:  ()  => {
        // Final flush before marking done
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
    setShowInference(true)

    inferenceRef.current?.close()
    inferenceRef.current = streamInference(user.user_id, {
      onChunk: chunk => setInferenceRaw(t => t + chunk),
      onError: msg  => { setInferenceError(msg); setInferencing(false) },
      onDone:  raw  => {
        const parsed = tryParseInference(raw)
        setInferenceResult(parsed)
        setInferencing(false)
      },
    })
  }

  useEffect(() => {
    sourceRef.current?.close()
    inferenceRef.current?.close()

    // Cancel any in-flight rAF flush for the previous user
    if (rafHandle.current) { cancelAnimationFrame(rafHandle.current); rafHandle.current = null }
    proseBuf.current = ''
    daBuf.current    = ''

    setProsecution(''); setDa(''); setSection(null)
    setStreaming(false); setDone(false); setError(null)
    setInferenceRaw(''); setInferenceResult(null); setInferenceError(null); setShowInference(false)

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
      <section className="card" style={{ padding: 14, flexShrink: 0 }}>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: 100, gap: 8, textAlign: 'center' }}>
          <BrainCircuit size={24} style={{ color: 'var(--text-muted)' }} />
          <p style={{ fontSize: 12, color: 'var(--text-muted)' }}>Select a user to generate<br />a two-pass LLM narrative</p>
        </div>
      </section>
    )
  }

  const cachedNarrative = narrative || user?.narrative
  const severity   = cachedNarrative?.final_severity
  const doubtScore = cachedNarrative?.doubt_score ?? null
  const canInfer   = done && (prosecution || da)

  return (
    <section className="card slide-up" style={{ padding: 14, flexShrink: 0 }}>

      {/* ── Header ── */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8, marginBottom: 10 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.09em', color: 'var(--text-muted)', marginBottom: 4 }}>
            <BrainCircuit size={11} /> Devil's Advocate Narrative
          </div>
          <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-primary)' }}>{user.username}</div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          {severity && <span className={SEVERITY_BG[severity] || 'badge-neutral'}>{severity}</span>}
          <button
            id={`narrative-refresh-${user.user_id}`}
            onClick={start}
            disabled={streaming}
            className="btn-icon"
            style={{ width: 28, height: 28, border: '1px solid var(--border)' }}
            title="Re-generate narrative"
          >
            {streaming ? <Loader2 size={12} className="spin-slow" /> : <RefreshCw size={12} />}
          </button>
        </div>
      </div>

      {/* ── Doubt score ── */}
      {doubtScore !== null && (
        <div style={{ marginBottom: 10 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>
            <span>Doubt Score</span>
            <span className="mono" style={{ color: 'var(--text-secondary)' }}>{(doubtScore * 100).toFixed(0)}%</span>
          </div>
          <div className="doubt-track">
            <div className="doubt-fill" style={{ width: `${doubtScore * 100}%` }} />
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--text-muted)', marginTop: 3 }}>
            <span>0 = Certain threat</span>
            <span>1 = Likely false positive</span>
          </div>
        </div>
      )}

      {/* ── Tab switcher ── */}
      <div style={{
        display: 'flex', gap: 4, padding: 3, borderRadius: 4,
        border: '1px solid var(--border)', background: 'var(--surface-mid)', marginBottom: 10,
      }}>
        {[
          { key: 'prosecutor', label: 'Prosecutor',      icon: AlertOctagon },
          { key: 'da',        label: "Devil's Advocate", icon: Scale         },
        ].map(({ key, label, icon: Icon }) => (
          <button
            key={key}
            id={`narrative-tab-${key}`}
            onClick={() => setTab(key)}
            style={{
              flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 5,
              padding: '5px 0', borderRadius: 3, border: 'none', fontSize: 11, fontWeight: 500, cursor: 'pointer',
              background: tab === key ? 'var(--surface)' : 'transparent',
              color: tab === key ? 'var(--text-primary)' : 'var(--text-muted)',
              transition: 'all 150ms ease',
            }}
          >
            <Icon size={11} style={{ color: tab === key ? 'var(--sg-red)' : 'inherit' }} /> {label}
          </button>
        ))}
      </div>

      {/* ── Generate button (if not started) ── */}
      {!streaming && !done && !prosecution && (
        <button
          id={`narrative-generate-${user.user_id}`}
          onClick={start}
          className="btn-primary"
          style={{ width: '100%', justifyContent: 'center', height: 36, marginBottom: 8 }}
        >
          <MessageSquareWarning size={13} /> Generate LLM Narrative
        </button>
      )}

      {/* ── Error ── */}
      {error && (
        <div style={{ marginBottom: 8, borderRadius: 4, border: '1px solid var(--c-critical-bd)', background: 'var(--c-critical-bg)', padding: '8px 10px', fontSize: 12, color: 'var(--c-critical)' }}>
          ⚠ {error}
        </div>
      )}

      {/* ── Content ── */}
      {(prosecution || da) && (
        <div>
          <div
            className={streaming && tab === activeSection ? 'cursor' : ''}
            style={{
              minHeight: 96, borderRadius: 4, border: '1px solid var(--border)',
              background: 'var(--surface-mid)', padding: '10px 12px',
              fontSize: 12, lineHeight: 1.65, color: 'var(--text-secondary)',
            }}
          >
            {tab === 'prosecutor'
              ? (prosecution || <span style={{ color: 'var(--text-muted)' }}>Waiting for Prosecutor…</span>)
              : (da           || <span style={{ color: 'var(--text-muted)' }}>Waiting for Devil's Advocate…</span>)
            }
          </div>

          {/* Recommendation */}
          {done && cachedNarrative?.recommendation && (
            <div style={{ marginTop: 8, borderRadius: 4, border: '1px solid var(--c-info-bd)', background: 'var(--c-info-bg)', padding: '8px 10px' }}>
              <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--c-info)', marginBottom: 4 }}>Recommendation</div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{cachedNarrative.recommendation}</div>
            </div>
          )}

          {/* Model attribution */}
          {done && (cachedNarrative?.prosecutor_model || cachedNarrative?.da_model) && (
            <div style={{ marginTop: 6, display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--text-muted)' }}>
              <span>⚖ {cachedNarrative.prosecutor_model}</span>
              <span>🛡 {cachedNarrative.da_model}</span>
            </div>
          )}
        </div>
      )}

      {/* ── Inference Button ── */}
      {canInfer && (
        <button
          id={`narrative-inference-${user.user_id}`}
          onClick={runInference}
          disabled={inferencing}
          className="btn-primary"
          style={{ width: '100%', justifyContent: 'center', height: 34, marginTop: 10 }}
        >
          {inferencing
            ? <><Loader2 size={13} className="spin-slow" /> Synthesising Verdict…</>
            : <><Gavel size={13} /> Inference — Final Verdict</>
          }
        </button>
      )}

      {/* ── Inference Error ── */}
      {inferenceError && (
        <div style={{ marginTop: 8, borderRadius: 4, border: '1px solid var(--c-critical-bd)', background: 'var(--c-critical-bg)', padding: '8px 10px', fontSize: 12, color: 'var(--c-critical)' }}>
          ⚠ Inference error: {inferenceError}
        </div>
      )}

      {/* ── Inference Result Panel ── */}
      {showInference && (inferencing || inferenceResult || inferenceRaw) && (
        <div style={{ marginTop: 10, borderRadius: 4, border: '1px solid var(--c-critical-bd)', overflow: 'hidden' }}>

          {/* Panel header toggle */}
          <button
            onClick={() => setShowInference(v => !v)}
            style={{
              width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              padding: '8px 12px', background: 'var(--c-critical-bg)', border: 'none', cursor: 'pointer',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <Gavel size={12} style={{ color: 'var(--c-critical)' }} />
              <span style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--c-critical)' }}>
                Final Verdict
              </span>
              {inferenceResult?.recommended_action && (
                <span className={ACTION_BG[inferenceResult.recommended_action] || 'badge-review'} style={{ marginLeft: 4 }}>
                  {inferenceResult.recommended_action}
                </span>
              )}
            </div>
            {showInference
              ? <ChevronUp  size={13} style={{ color: 'var(--text-muted)' }} />
              : <ChevronDown size={13} style={{ color: 'var(--text-muted)' }} />
            }
          </button>

          {showInference && (
            <div style={{ padding: '10px 12px', display: 'flex', flexDirection: 'column', gap: 8, background: 'var(--surface-mid)' }}>

              {/* Streaming raw */}
              {inferencing && !inferenceResult && (
                <div style={{ borderRadius: 4, border: '1px solid var(--border)', background: 'var(--surface)', padding: '8px 10px', fontSize: 11, fontFamily: 'monospace', color: 'var(--text-muted)', minHeight: 48 }}>
                  {inferenceRaw || <span style={{ opacity: 0.5 }}>Generating verdict…</span>}
                </div>
              )}

              {/* Parsed result */}
              {inferenceResult && (
                <>
                  {/* Confidence */}
                  {inferenceResult.confidence && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11 }}>
                      <span style={{ textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)' }}>Confidence</span>
                      <span style={{ fontWeight: 700, color: CONFIDENCE_COLOR[inferenceResult.confidence] || 'var(--text-secondary)' }}>
                        {inferenceResult.confidence}
                      </span>
                    </div>
                  )}

                  {/* What happened */}
                  {inferenceResult.what_happened && (
                    <div style={{ borderRadius: 4, border: '1px solid var(--border)', background: 'var(--surface)', padding: '8px 10px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 5 }}>
                        <ShieldAlert size={10} /> What Actually Happened
                      </div>
                      <p style={{ fontSize: 12, lineHeight: 1.55, color: 'var(--text-secondary)', margin: 0 }}>{inferenceResult.what_happened}</p>
                    </div>
                  )}

                  {/* Key findings */}
                  {inferenceResult.key_findings?.length > 0 && (
                    <div style={{ borderRadius: 4, border: '1px solid var(--c-review-bd)', background: 'var(--c-review-bg)', padding: '8px 10px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--c-review)', marginBottom: 6 }}>
                        <ListChecks size={10} /> Key Findings
                      </div>
                      <ul style={{ margin: 0, padding: 0, listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 4 }}>
                        {inferenceResult.key_findings.map((f, i) => (
                          <li key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 6, fontSize: 12, color: 'var(--text-secondary)' }}>
                            <span style={{ width: 5, height: 5, borderRadius: '50%', background: 'var(--c-review)', marginTop: 5, flexShrink: 0 }} />
                            {f}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Remediation steps */}
                  {inferenceResult.remediation_steps?.length > 0 && (
                    <div style={{ borderRadius: 4, border: '1px solid var(--c-normal-bd)', background: 'var(--c-normal-bg)', padding: '8px 10px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--c-normal)', marginBottom: 6 }}>
                        <CheckCircle2 size={10} /> Remediation Steps
                      </div>
                      <ol style={{ margin: 0, padding: 0, listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 5 }}>
                        {inferenceResult.remediation_steps.map((step, i) => (
                          <li key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 6, fontSize: 12, color: 'var(--text-secondary)' }}>
                            <span style={{
                              width: 16, height: 16, borderRadius: '50%', flexShrink: 0, marginTop: 1,
                              display: 'flex', alignItems: 'center', justifyContent: 'center',
                              background: 'var(--c-normal-bg)', color: 'var(--c-normal)', fontSize: 9, fontWeight: 700,
                            }}>
                              {i + 1}
                            </span>
                            {step}
                          </li>
                        ))}
                      </ol>
                    </div>
                  )}

                  {/* Rationale */}
                  {inferenceResult.rationale && (
                    <div style={{ paddingTop: 8, borderTop: '1px solid var(--border)', fontSize: 11, fontStyle: 'italic', color: 'var(--text-muted)' }}>
                      {inferenceResult.rationale}
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </div>
      )}
    </section>
  )
}
