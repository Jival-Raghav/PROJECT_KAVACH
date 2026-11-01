import { useRun } from '../../run'

// Extra datasets analysed as batch runs, shown in their own dropdown under friendly names.
export const BONUS_RUNS = [
  { id: 'estate-bonus', label: 'Estate bonus' },
]
const BONUS_IDS = new Set(BONUS_RUNS.map(b => b.id))

export default function RunSelector() {
  const { runId, selectRun, runs, refreshRuns } = useRun()
  const live = runs.filter(r => r.kind === 'live')
  const onBonus = BONUS_IDS.has(runId)
  const known = runId === 'firex' || onBonus || live.some(r => r.run_id === runId)
  const ready = new Set(runs.map(r => r.run_id))
  return (
    <>
      <select
        className="run-select"
        value={onBonus ? '' : runId}
        onChange={e => selectRun(e.target.value)}
        aria-label="Select run"
        title="Select run"
      >
        {onBonus && <option value="" disabled hidden>Main runs</option>}
        <option value="firex">firex</option>
        {!known && <option value={runId}>{runId}</option>}
        {live.map(r => (
          <option key={r.run_id} value={r.run_id}>{r.run_id} · {r.status}</option>
        ))}
      </select>
      <select
        className="run-select"
        value={onBonus ? runId : ''}
        onChange={e => selectRun(e.target.value)}
        aria-label="Select bonus dataset"
        onMouseDown={refreshRuns}
        onFocus={refreshRuns}
        title="Bonus datasets"
      >
        <option value="" disabled hidden>Bonus datasets</option>
        {BONUS_RUNS.map(b => (
          <option key={b.id} value={b.id} disabled={!ready.has(b.id)}>
            {b.label}{ready.has(b.id) ? '' : ' · running…'}
          </option>
        ))}
      </select>
    </>
  )
}
