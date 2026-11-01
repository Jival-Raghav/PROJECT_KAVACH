import { useRun } from '../../run'

export default function RunSelector() {
  const { runId, selectRun, runs } = useRun()
  const live = runs.filter(r => r.kind === 'live')
  const known = runId === 'firex' || live.some(r => r.run_id === runId)
  return (
    <select
      className="run-select"
      value={runId}
      onChange={e => selectRun(e.target.value)}
      aria-label="Select run"
      title="Select run"
    >
      <option value="firex">firex</option>
      {!known && <option value={runId}>{runId}</option>}
      {live.map(r => (
        <option key={r.run_id} value={r.run_id}>{r.run_id} · {r.status}</option>
      ))}
    </select>
  )
}
