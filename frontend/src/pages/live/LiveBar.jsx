import { Radio } from 'lucide-react'
import { startLive, stopLive } from '../../api'
import { useRun } from '../../run'

const BADGE = {
  complete: 'badge-normal', stopped: 'badge-review', interrupted: 'badge-review', error: 'badge-critical',
}

export default function LiveBar() {
  const { runId, live, refreshLive } = useRun()
  if (!live) return null

  const processing = live.status === 'processing'
  const total = live.bytes_total || 0
  const pct = live.status === 'complete' ? 100
    : total > 0 ? Math.min(100, Math.floor((live.bytes_read / total) * 100)) : 0
  const time = live.last_cycle_at ? new Date(live.last_cycle_at).toLocaleTimeString() : '-'
  const resumable = live.status === 'stopped' || live.status === 'interrupted'

  const stop = () => stopLive(runId).catch(() => {}).then(refreshLive)
  const resume = () => startLive(live.path, runId).catch(() => {}).then(refreshLive)

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
      {processing && pct < 25 && (
        <span className="live-early kc-muted">
          <Radio size={12} /> Early results: history-based findings may still change
        </span>
      )}
      {live.status === 'error' && live.error && <span className="live-err">{live.error}</span>}
      <span className="live-spacer" />
      {processing && <button className="btn-ghost" onClick={stop}>Stop</button>}
      {resumable && <button className="btn-ghost" onClick={resume}>Resume</button>}
    </div>
  )
}
