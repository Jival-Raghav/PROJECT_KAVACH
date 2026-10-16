import { Activity, AlertTriangle, CheckCircle2, Cpu, Loader2, Play, Zap } from 'lucide-react'

const statusConfig = {
  idle:     { label: 'Idle',     icon: Activity,     ring: 'border-white/10', bg: 'bg-white/5',        dot: 'bg-slate-400' },
  running:  { label: 'Running',  icon: Loader2,      ring: 'border-cyan-500/40', bg: 'bg-cyan-500/5', dot: 'bg-cyan-400 pulse-dot' },
  complete: { label: 'Complete', icon: CheckCircle2, ring: 'border-emerald-500/40', bg: 'bg-emerald-500/5', dot: 'bg-emerald-400' },
  error:    { label: 'Error',    icon: AlertTriangle,ring: 'border-rose-500/40', bg: 'bg-rose-500/5', dot: 'bg-rose-400' },
}

export default function StatusBar({ status, progress, message, onRunPipeline, llmStatus, lastRun }) {
  const cfg = statusConfig[status] ?? statusConfig.idle
  const Icon = cfg.icon
  const isRunning = status === 'running'

  return (
    <header className={`glass rounded-2xl border ${cfg.ring} ${cfg.bg} p-5 shadow-2xl transition-colors duration-500`}>
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        {/* Left: title + status */}
        <div className="flex items-center gap-4">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-500/20 to-indigo-500/20 ring-1 ring-white/10">
            <Icon size={18} className={isRunning ? 'spin-slow text-cyan-400' : 'text-cyan-300'} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="grad-text text-lg font-bold tracking-tight">ISPAD</h1>
              <span className="text-xs text-slate-500">Identity Sprawl & Privilege Abuse Detection</span>
            </div>
            <div className="mt-0.5 flex items-center gap-2 text-xs text-slate-400">
              <span className={`inline-block h-1.5 w-1.5 rounded-full ${cfg.dot}`} />
              {message || cfg.label}
              {lastRun && <span className="text-slate-600">· Last run {new Date(lastRun).toLocaleTimeString()}</span>}
            </div>
          </div>
        </div>

        {/* Right: LLM status + run button */}
        <div className="flex items-center gap-3">
          {/* LLM provider pills */}
          {llmStatus && (
            <div className="hidden items-center gap-2 md:flex">
              <LLMPill label="LM Studio" ok={llmStatus.prosecutor?.available} role="Prosecutor" />
              <LLMPill label="Ollama" ok={llmStatus.devils_advocate?.available} role="Devil's Advocate" />
            </div>
          )}

          <button
            id="run-pipeline-btn"
            onClick={onRunPipeline}
            disabled={isRunning}
            className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-indigo-500 px-5 py-2.5 text-sm font-semibold text-white shadow-lg shadow-cyan-500/20 transition hover:scale-[1.02] hover:shadow-cyan-500/30 disabled:cursor-not-allowed disabled:opacity-50 active:scale-[0.98]"
          >
            {isRunning ? <Loader2 size={15} className="spin-slow" /> : <Play size={15} />}
            {isRunning ? 'Running…' : 'Run Pipeline'}
          </button>
        </div>
      </div>

      {/* Progress bar */}
      {isRunning && (
        <div className="mt-4 slide-up">
          <div className="mb-1.5 flex items-center justify-between text-[11px] uppercase tracking-widest text-slate-400">
            <span>Analysing {progress < 40 ? 'users' : progress < 70 ? 'events' : progress < 90 ? 'compliance' : 'finalising'}</span>
            <span className="font-mono text-cyan-400">{progress}%</span>
          </div>
          <div className="risk-bar">
            <div
              className="risk-bar-fill bg-gradient-to-r from-cyan-500 to-indigo-500"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      )}
    </header>
  )
}

function LLMPill({ label, ok, role }) {
  return (
    <div
      title={role}
      className={`flex items-center gap-1.5 rounded-full border px-3 py-1 text-[11px] font-medium transition ${
        ok
          ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
          : 'border-white/10 bg-white/5 text-slate-500'
      }`}
    >
      <Cpu size={10} />
      {label}
      <span className={`h-1.5 w-1.5 rounded-full ${ok ? 'bg-emerald-400 pulse-dot' : 'bg-slate-600'}`} />
    </div>
  )
}
