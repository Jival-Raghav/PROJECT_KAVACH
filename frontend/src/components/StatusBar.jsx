export default function StatusBar({ status, progress, message, onRunPipeline }) {
  const statusStyles = {
    idle: 'border-slate-600 bg-slate-900/80 text-slate-200',
    running: 'border-blue-500/50 bg-blue-500/10 text-blue-100',
    complete: 'border-emerald-500/50 bg-emerald-500/10 text-emerald-100',
    error: 'border-rose-500/50 bg-rose-500/10 text-rose-100'
  }

  return (
    <header className={`rounded-[2rem] border p-5 shadow-2xl shadow-black/20 ${statusStyles[status] ?? statusStyles.idle}`}>
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <div className="text-xs uppercase tracking-[0.35em] opacity-70">Pipeline</div>
          <div className="mt-1 text-2xl font-semibold">{status.toUpperCase()}</div>
          <div className="mt-1 text-sm opacity-80">{message || 'Waiting to start.'}</div>
        </div>
        <button
          onClick={onRunPipeline}
          disabled={status === 'running'}
          className="rounded-2xl bg-white px-5 py-3 text-sm font-semibold text-slate-950 transition hover:scale-[1.01] disabled:cursor-not-allowed disabled:opacity-50"
        >
          Run Pipeline
        </button>
      </div>

      {status === 'running' ? (
        <div className="mt-5">
          <div className="mb-2 flex items-center justify-between text-xs uppercase tracking-[0.3em] opacity-70">
            <span>Progress</span>
            <span>{progress}%</span>
          </div>
          <div className="h-3 rounded-full bg-white/10">
            <div className="h-3 rounded-full bg-gradient-to-r from-cyan-400 to-blue-500" style={{ width: `${progress}%` }} />
          </div>
        </div>
      ) : null}
    </header>
  )
}
