import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import { getLiveStatus, getRuns, setApiRunId } from './api'

const RunContext = createContext({
  runId: 'firex', selectRun: () => {}, runs: [], refreshRuns: () => {}, live: null, generation: 0,
})
export const useRun = () => useContext(RunContext)

export function RunProvider({ children }) {
  const [runId, setRunId] = useState('firex')
  const [runs, setRuns] = useState([])
  const [live, setLive] = useState(null)

  const refreshRuns = useCallback(
    () => getRuns().then(r => { setRuns(r); return r }).catch(() => []), [])

  // Pick the newest live run on first load, otherwise stay on firex.
  useEffect(() => {
    let off = false
    refreshRuns().then(r => {
      if (off) return
      const newest = r.find(x => x.kind === 'live')
      if (newest) { setApiRunId(newest.run_id); setRunId(newest.run_id) }
    })
    return () => { off = true }
  }, [refreshRuns])

  const selectRun = useCallback(id => { setApiRunId(id); setRunId(id) }, [])

  const isLive = runs.find(r => r.run_id === runId)?.kind === 'live'
  const status = live?.status

  // Load live state for live runs; keep polling while it is processing.
  useEffect(() => {
    if (!isLive) { setLive(null); return }
    let off = false
    const tick = () => getLiveStatus(runId).then(s => { if (!off) setLive(s) }).catch(() => {})
    tick()
    if (status !== 'processing') return () => { off = true }
    const t = setInterval(tick, 2000)
    return () => { off = true; clearInterval(t) }
  }, [runId, isLive, status])

  const value = useMemo(() => ({
    runId, selectRun, runs, refreshRuns, live, generation: live?.generation ?? 0,
  }), [runId, selectRun, runs, refreshRuns, live])

  return <RunContext.Provider value={value}>{children}</RunContext.Provider>
}
