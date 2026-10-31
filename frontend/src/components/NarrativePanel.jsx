import { useEffect, useRef, useState } from 'react'
import { streamNarrative, streamInference } from '../api'
import {
  BrainCircuit, MessageSquareWarning, Scale, AlertOctagon,
  Loader2, RefreshCw, Gavel, CheckCircle2, ListChecks,
  ShieldAlert, ChevronDown, ChevronUp
} from 'lucide-react'

const SEVERITY_STYLE = {
  CRITICAL:      'bg-rose-500/20 text-rose-200 border-rose-400/40',
  HIGH:          'bg-orange-500/20 text-orange-200 border-orange-400/40',
  REVIEW:        'bg-yellow-500/20 text-yellow-100 border-yellow-400/40',
  INFORMATIONAL: 'bg-slate-500/20 text-slate-200 border-slate-400/40',
  SUPPRESSED:    'bg-slate-700/30 text-slate-400 border-slate-600/40',
}

const ACTION_STYLE = {
  ESCALATE:    'bg-rose-500/20 text-rose-300 border-rose-400/40',
  INVESTIGATE: 'bg-orange-500/20 text-orange-300 border-orange-400/40',
  MONITOR:     'bg-yellow-500/20 text-yellow-200 border-yellow-400/40',
  DISMISS:     'bg-emerald-500/20 text-emerald-300 border-emerald-400/40',
}

const CONFIDENCE_STYLE = {
  HIGH:   'text-rose-300',
  MEDIUM: 'text-yellow-300',
  LOW:    'text-slate-400',
}

function tryParseInference(raw) {
  // strip markdown fences
  const cleaned = raw.replace(/```(?:json)?\s*/g, '').replace(/```/g, '').trim()
  const start = cleaned.indexOf('{')
  const end   = cleaned.lastIndexOf('}')
  if (start === -1 || end === -1) return null
  try { return JSON.parse(cleaned.slice(start, end + 1)) } catch { return null }
}

export default function NarrativePanel({ user }) {
  const [prosecution, setProsecution]   = useState('')
  const [da,          setDa]            = useState('')
  const [activeSection, setSection]     = useState(null)
  const [streaming,   setStreaming]      = useState(false)
  const [done,        setDone]          = useState(false)
  const [error,       setError]         = useState(null)
  const [narrative,   setNarrative]     = useState(null)
  const [tab,         setTab]           = useState('prosecutor')

  // Inference state
  const [inferencing,    setInferencing]    = useState(false)
  const [inferenceRaw,   setInferenceRaw]   = useState('')
  const [inferenceResult, setInferenceResult] = useState(null)
  const [inferenceError, setInferenceError]  = useState(null)
  const [showInference,  setShowInference]   = useState(false)

  const sourceRef    = useRef(null)
  const inferenceRef = useRef(null)

  const start = () => {
    if (!user?.user_id) return
    setProsecution(''); setDa(''); setSection(null)
    setStreaming(true); setDone(false); setError(null); setNarrative(null)
    // reset inference when re-generating narrative
    setInferenceRaw(''); setInferenceResult(null); setInferenceError(null); setShowInference(false)

    sourceRef.current?.close()
    sourceRef.current = streamNarrative(user.user_id, {
      onSection: s => { setSection(s); setTab(s) },
      onChunk:   chunk => {
        setSection(prev => {
          if (prev === 'prosecutor') setProsecution(t => t + chunk)
          else if (prev === 'da')   setDa(t => t + chunk)
          return prev
        })
      },
      onError:   msg => { setError(msg); setStreaming(false) },
      onDone:    () => { setStreaming(false); setDone(true) },
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

  // Auto-load cached narrative when user changes
  useEffect(() => {
    sourceRef.current?.close()
    inferenceRef.current?.close()
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
    }
  }, [user?.user_id])

  if (!user) {
    return (
      <section className="glass rounded-2xl border border-white/10 p-5">
        <div className="flex h-40 flex-col items-center justify-center gap-3 text-center">
          <BrainCircuit size={28} className="text-slate-600" />
          <p className="text-sm text-slate-500">Select a user to generate a<br />two-pass LLM narrative</p>
        </div>
      </section>
    )
  }

  const cachedNarrative = narrative || user?.narrative
  const severity   = cachedNarrative?.final_severity
  const doubtScore = cachedNarrative?.doubt_score ?? null
  const canInfer   = done && (prosecution || da)

  return (
    <section className="glass rounded-2xl border border-white/10 p-5 slide-up">
      {/* Header */}
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 text-[11px] uppercase tracking-widest text-slate-500">
            <BrainCircuit size={12} /> Devil's Advocate Narrative
          </div>
          <div className="mt-1 font-semibold text-white">{user.username}</div>
        </div>
        <div className="flex items-center gap-2">
          {severity && (
            <span className={`chip border ${SEVERITY_STYLE[severity] || SEVERITY_STYLE.INFORMATIONAL}`}>
              {severity}
            </span>
          )}
          <button
            id={`narrative-refresh-${user.user_id}`}
            onClick={start}
            disabled={streaming}
            className="flex h-7 w-7 items-center justify-center rounded-lg border border-white/10 bg-white/5 text-slate-400 transition hover:bg-white/10 hover:text-white disabled:opacity-40"
            title="Re-generate narrative"
          >
            {streaming ? <Loader2 size={13} className="spin-slow" /> : <RefreshCw size={13} />}
          </button>
        </div>
      </div>

      {/* Doubt score meter */}
      {doubtScore !== null && (
        <div className="mt-4">
          <div className="mb-1 flex justify-between text-[11px] text-slate-500">
            <span>Doubt Score (DA confidence)</span>
            <span className="mono text-slate-300">{(doubtScore * 100).toFixed(0)}%</span>
          </div>
          <div className="doubt-track">
            <div className="doubt-fill" style={{ width: `${doubtScore * 100}%` }} />
          </div>
          <div className="mt-1 flex justify-between text-[10px] text-slate-600">
            <span>0 = Certain threat</span><span>1 = Likely false positive</span>
          </div>
        </div>
      )}

      {/* Tab switcher */}
      <div className="mt-4 flex gap-1 rounded-xl border border-white/8 bg-white/5 p-1">
        {[
          { key: 'prosecutor', label: 'Prosecutor',      icon: AlertOctagon, color: 'text-orange-300' },
          { key: 'da',        label: "Devil's Advocate", icon: Scale,        color: 'text-cyan-300'   },
        ].map(({ key, label, icon: Icon, color }) => (
          <button
            key={key}
            id={`narrative-tab-${key}`}
            onClick={() => setTab(key)}
            className={`flex flex-1 items-center justify-center gap-1.5 rounded-lg py-1.5 text-xs font-medium transition ${
              tab === key ? 'bg-white/10 text-white shadow' : 'text-slate-500 hover:text-slate-300'
            }`}
          >
            <Icon size={11} className={tab === key ? color : ''} /> {label}
          </button>
        ))}
      </div>

      {/* Generate button (if not started) */}
      {!streaming && !done && !prosecution && (
        <button
          id={`narrative-generate-${user.user_id}`}
          onClick={start}
          className="mt-4 w-full rounded-xl border border-cyan-500/30 bg-cyan-500/10 py-3 text-sm font-medium text-cyan-300 transition hover:bg-cyan-500/20"
        >
          <MessageSquareWarning size={14} className="mr-2 inline" />
          Generate LLM Narrative
        </button>
      )}

      {/* Error */}
      {error && (
        <div className="mt-3 rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-300">
          ⚠ {error}
        </div>
      )}

      {/* Content */}
      {(prosecution || da) && (
        <div className="mt-3">
          <div className={`min-h-32 rounded-xl border border-white/8 bg-white/4 p-4 text-sm leading-relaxed text-slate-300 slide-up ${
            streaming && tab === activeSection ? 'cursor' : ''
          }`}>
            {tab === 'prosecutor'
              ? (prosecution || <span className="text-slate-600">Waiting for Prosecutor…</span>)
              : (da || <span className="text-slate-600">Waiting for Devil's Advocate…</span>)
            }
          </div>

          {/* Recommendation */}
          {done && cachedNarrative?.recommendation && (
            <div className="mt-3 rounded-xl border border-indigo-500/20 bg-indigo-500/8 p-3">
              <div className="mb-1 text-[10px] uppercase tracking-widest text-indigo-400">Recommendation</div>
              <div className="text-xs text-slate-300">{cachedNarrative.recommendation}</div>
            </div>
          )}

          {/* Model attribution */}
          {done && (cachedNarrative?.prosecutor_model || cachedNarrative?.da_model) && (
            <div className="mt-2 flex items-center justify-between text-[10px] text-slate-600">
              <span>⚖ {cachedNarrative.prosecutor_model}</span>
              <span>🛡 {cachedNarrative.da_model}</span>
            </div>
          )}
        </div>
      )}

      {/* ── Inference Button ─────────────────────────────────────── */}
      {canInfer && (
        <button
          id={`narrative-inference-${user.user_id}`}
          onClick={runInference}
          disabled={inferencing}
          className={`mt-4 w-full rounded-xl border py-3 text-sm font-semibold transition flex items-center justify-center gap-2 ${
            inferencing
              ? 'border-violet-500/20 bg-violet-500/5 text-violet-400 opacity-70 cursor-not-allowed'
              : 'border-violet-500/40 bg-violet-500/15 text-violet-300 hover:bg-violet-500/25 hover:border-violet-400/60 shadow-[0_0_20px_rgba(139,92,246,0.12)]'
          }`}
        >
          {inferencing
            ? <><Loader2 size={14} className="spin-slow" /> Synthesising Verdict…</>
            : <><Gavel size={14} /> Inference — Final Verdict</>
          }
        </button>
      )}

      {/* ── Inference Error ──────────────────────────────────────── */}
      {inferenceError && (
        <div className="mt-3 rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-300">
          ⚠ Inference error: {inferenceError}
        </div>
      )}

      {/* ── Inference Result Panel ───────────────────────────────── */}
      {showInference && (inferencing || inferenceResult || inferenceRaw) && (
        <div className="mt-3 rounded-2xl border border-violet-500/25 bg-violet-500/8 overflow-hidden slide-up">
          {/* Panel header */}
          <button
            onClick={() => setShowInference(v => !v)}
            className="w-full flex items-center justify-between px-4 py-3 text-left"
          >
            <div className="flex items-center gap-2">
              <Gavel size={13} className="text-violet-400" />
              <span className="text-xs font-semibold uppercase tracking-widest text-violet-300">
                Final Verdict
              </span>
              {inferenceResult?.recommended_action && (
                <span className={`ml-1 rounded-md border px-2 py-0.5 text-[10px] font-bold ${
                  ACTION_STYLE[inferenceResult.recommended_action] || ACTION_STYLE.MONITOR
                }`}>
                  {inferenceResult.recommended_action}
                </span>
              )}
            </div>
            {showInference ? <ChevronUp size={13} className="text-slate-500" /> : <ChevronDown size={13} className="text-slate-500" />}
          </button>

          {showInference && (
            <div className="px-4 pb-4 space-y-3">
              {/* Streaming raw while inferencing */}
              {inferencing && !inferenceResult && (
                <div className="rounded-xl border border-white/8 bg-white/4 p-3 text-xs leading-relaxed text-slate-400 font-mono min-h-16">
                  {inferenceRaw || <span className="text-slate-600 animate-pulse">Generating verdict…</span>}
                </div>
              )}

              {/* Parsed structured result */}
              {inferenceResult && (
                <>
                  {/* Confidence badge */}
                  {inferenceResult.confidence && (
                    <div className="flex items-center gap-2 text-[11px]">
                      <span className="text-slate-500 uppercase tracking-widest">Confidence</span>
                      <span className={`font-bold ${CONFIDENCE_STYLE[inferenceResult.confidence] || 'text-slate-400'}`}>
                        {inferenceResult.confidence}
                      </span>
                    </div>
                  )}

                  {/* What happened */}
                  {inferenceResult.what_happened && (
                    <div className="rounded-xl border border-white/8 bg-white/4 p-3">
                      <div className="mb-1.5 text-[10px] uppercase tracking-widest text-slate-500 flex items-center gap-1">
                        <ShieldAlert size={10} /> What Actually Happened
                      </div>
                      <p className="text-xs leading-relaxed text-slate-300">
                        {inferenceResult.what_happened}
                      </p>
                    </div>
                  )}

                  {/* Key findings */}
                  {inferenceResult.key_findings?.length > 0 && (
                    <div className="rounded-xl border border-amber-500/15 bg-amber-500/8 p-3">
                      <div className="mb-2 text-[10px] uppercase tracking-widest text-amber-400 flex items-center gap-1">
                        <ListChecks size={10} /> Key Findings
                      </div>
                      <ul className="space-y-1">
                        {inferenceResult.key_findings.map((f, i) => (
                          <li key={i} className="flex items-start gap-1.5 text-xs text-slate-300">
                            <span className="mt-0.5 h-1.5 w-1.5 shrink-0 rounded-full bg-amber-400/60" />
                            {f}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Remediation steps */}
                  {inferenceResult.remediation_steps?.length > 0 && (
                    <div className="rounded-xl border border-emerald-500/15 bg-emerald-500/8 p-3">
                      <div className="mb-2 text-[10px] uppercase tracking-widest text-emerald-400 flex items-center gap-1">
                        <CheckCircle2 size={10} /> Remediation Steps
                      </div>
                      <ol className="space-y-1.5">
                        {inferenceResult.remediation_steps.map((step, i) => (
                          <li key={i} className="flex items-start gap-2 text-xs text-slate-300">
                            <span className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-emerald-500/20 text-[9px] font-bold text-emerald-400">
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
                    <div className="border-t border-white/8 pt-3 text-[11px] italic text-slate-500">
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
