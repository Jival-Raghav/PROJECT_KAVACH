import { useState } from 'react'
import { Radio } from 'lucide-react'
import { startLive, stopLive } from '../../api'
import { useRun } from '../../run'

const BADGE = {
  complete: 'badge-normal', stopped: 'badge-review', interrupted: 'badge-review', error: 'badge-critical',
}

export default function LiveBar() {
  const { runId, live, refreshLive } = useRun()
  const [error, setError] = useState('')
  if (!live) return null

  const processing = live.status === 'processing'
  const total = live.bytes_total || 0
  const pct = live.status === 'complete' ? 100
    : total > 0 ? Math.min(100, Math.floor((live.bytes_read / total) * 100)) : 0
  const time = live.last_cycle_at ? new Date(live.last_cycle_at).toLocaleTimeString() : '-'
  const resumable = ['stopped', 'interrupted', 'error'].includes(live.status) && !!live.path

  const act = call => {
    setError('')
    return call()
      .catch(err => setError(typeof err.detail === 'string' ? err.detail : err.message))
      .then(refreshLive)
  }
  const stop = () => act(() => stopLive(runId))
  const resume = () => {
    if (!live.path) { setError('This run has no log path to resume from'); return }
    act(() => startLive(live.path, runId))
  }

  return (
    <div className="live-bar">
      {processing
        ? <span className="chip live-chip"><span className="live-dot" /> Live</span>
        : <span className={BADGE[live.status] || 'badge-neutral'}>{live.status}</span>}
      <div className="live-progress" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}>
        <div style={{ width: `${pct}%` }} />
      </div>
      <span className="live-text">
        {pct}% · {(live.lines_parsed ?? 0).toLocaleString()} lines · update {live.generation ?? 0} · last update {time}
      </span>
      {live.parser && (
        <span className="chip" title={live.schema_path || 'Standard FortiGate key=value parser'}>
          {live.parser === 'schema'
            ? `Parser: learned format (${live.schema_path.split(/[\\/]/).pop().replace(/\.ya?ml$/, '')})`
            : 'Parser: FortiGate'}
        </span>
      )}
      {processing && pct < 25 && (
        <span className="live-early kc-muted">
          <Radio size={12} /> Early results: history-based findings may still change
        </span>
      )}
      {live.status === 'error' && live.error && <span className="live-err">{live.error}</span>}
      {error && <span className="live-err" role="alert">{error}</span>}
      <span className="live-spacer" />
      {processing && <button className="btn-ghost" onClick={stop}>Stop</button>}
      {resumable && <button className="btn-ghost" onClick={resume}>Resume</button>}
    </div>
  )
}
