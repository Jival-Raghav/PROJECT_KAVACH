import { useEffect, useRef, useState } from 'react'
import { streamNarrative } from '../api'
import { BrainCircuit, MessageSquareWarning, Scale, AlertOctagon, Loader2, RefreshCw } from 'lucide-react'

const SEVERITY_STYLE = {
  CRITICAL:      'bg-rose-500/20 text-rose-200 border-rose-400/40',
  HIGH:          'bg-orange-500/20 text-orange-200 border-orange-400/40',
  REVIEW:        'bg-yellow-500/20 text-yellow-100 border-yellow-400/40',
  INFORMATIONAL: 'bg-slate-500/20 text-slate-200 border-slate-400/40',
  SUPPRESSED:    'bg-slate-700/30 text-slate-400 border-slate-600/40',
}

export default function NarrativePanel({ user }) {
  const [prosecution, setProsecution]   = useState('')
  const [da,          setDa]            = useState('')
  const [activeSection, setSection]     = useState(null)   // 'prosecutor' | 'da'
  const [streaming,   setStreaming]      = useState(false)
  const [done,        setDone]          = useState(false)
  const [error,       setError]         = useState(null)
  const [narrative,   setNarrative]     = useState(null)   // cached narrative from profile
  const [tab,         setTab]           = useState('prosecutor')
  const sourceRef = useRef(null)

  const start = () => {
    if (!user?.user_id) return
    // Reset
    setProsecution(''); setDa(''); setSection(null)
    setStreaming(true); setDone(false); setError(null); setNarrative(null)

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

  // Auto-start when user changes; also pick up cached narrative
  useEffect(() => {
    sourceRef.current?.close()
    setProsecution(''); setDa(''); setSection(null)
    setStreaming(false); setDone(false); setError(null)

    if (user?.narrative) {
      setNarrative(user.narrative)
      setProsecution(user.narrative.prosecution || '')
      setDa(user.narrative.devils_advocate || '')
      setDone(true)
    } else {
      setNarrative(null)
    }

    return () => sourceRef.current?.close()
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
  const severity = cachedNarrative?.final_severity
  const doubtScore = cachedNarrative?.doubt_score ?? null

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
          { key: 'prosecutor', label: 'Prosecutor', icon: AlertOctagon, color: 'text-orange-300' },
          { key: 'da', label: "Devil's Advocate", icon: Scale, color: 'text-cyan-300' },
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
    </section>
  )
}
