const BASE_URL = 'http://localhost:8000'

const json = r => r.json()
const err  = async r => {
  if (!r.ok) {
    const text = await r.text()
    const e = new Error(text)
    try { e.detail = JSON.parse(text)?.detail } catch { /* body is not JSON */ }
    throw e
  }
  return r
}

// The run every kc() request is scoped to. 'firex' is the backend default, so it behaves as before.
let apiRunId = 'firex'
export const setApiRunId = id => { apiRunId = id }
const withRun = (path, id = apiRunId) =>
  `${path}${path.includes('?') ? '&' : '?'}run_id=${encodeURIComponent(id)}`
const kc   = path => fetch(`${BASE_URL}${withRun(path)}`).then(err).then(json)

export const getIncidents       = (minRisk = 0) => kc(`/api/incidents?min_risk=${minRisk}`)
export const getIncident        = id => kc(`/api/incidents/${id}`)
export const getIncidentPath    = id => kc(`/api/incidents/${id}/path`)
export const getIncidentNext    = id => kc(`/api/incidents/${id}/next`)
export const getIncidentReport  = (id, llm = false) => kc(`/api/incidents/${id}/report?llm=${llm}`)
export const getIncidentReview  = (id, llm = false) => kc(`/api/incidents/${id}/review?llm=${llm}`)
export const getResponseActions = () => kc('/api/response/actions')
export const getCompliance      = () => kc('/api/killchain/compliance')
export const getAccounts        = () => kc('/api/accounts')
export const getLlmSafety       = () => kc('/api/killchain/llm-safety')
export const getAnomalies       = (params = {}) => {
  const p = new URLSearchParams({ limit: 50, offset: 0, notable_only: true, ...params })
  return kc(`/api/anomalies?${p}`)
}
export const getActors          = () => kc('/api/actors')
export const getKillchainRules  = () => kc('/api/killchain/rules')
export const getKillchainStatus = () => kc('/api/killchain/status')
export const runKillchain       = (skipIngest = true) =>
  fetch(`${BASE_URL}${withRun(`/api/killchain/run?skip_ingest=${skipIngest}`)}`, { method: 'POST' }).then(err).then(json)

// Live mode: these take the run id explicitly rather than using the current selection.
export const getRuns        = () => fetch(`${BASE_URL}/api/runs`).then(err).then(json)
export const getLiveStatus  = runId =>
  fetch(`${BASE_URL}${withRun('/api/live/status', runId)}`).then(err).then(json)
export const getLiveChanges = (runId, sinceGeneration = 0) =>
  fetch(`${BASE_URL}${withRun(`/api/live/changes?since_generation=${sinceGeneration}`, runId)}`).then(err).then(json)
export const startLive      = (path, runId = null) =>
  fetch(`${BASE_URL}/api/live/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path, run_id: runId }),
  }).then(err).then(json)
export const stopLive       = runId =>
  fetch(`${BASE_URL}${withRun('/api/live/stop', runId)}`, { method: 'POST' }).then(err).then(json)
