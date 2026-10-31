const BASE_URL = 'http://localhost:8000'

const json = r => r.json()
const err  = async r => { if (!r.ok) throw new Error(await r.text()); return r }
const kc   = path => fetch(`${BASE_URL}${path}`).then(err).then(json)

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
  fetch(`${BASE_URL}/api/killchain/run?skip_ingest=${skipIngest}`, { method: 'POST' }).then(err).then(json)
