const BASE_URL = 'http://localhost:8000'

const json = r => r.json()
const err  = async r => { if (!r.ok) throw new Error(await r.text()); return r }

export const runPipeline  = () => fetch(`${BASE_URL}/run-pipeline`, { method: 'POST' }).then(err).then(json)
export const getStatus    = () => fetch(`${BASE_URL}/status`).then(err).then(json)
export const getUserRisks = () => fetch(`${BASE_URL}/users/risks`).then(err).then(json)
export const getUser      = id => fetch(`${BASE_URL}/users/${id}`).then(err).then(json)
export const getStats     = () => fetch(`${BASE_URL}/stats`).then(err).then(json)
export const getOrgAnomalies = () => fetch(`${BASE_URL}/org-anomalies`).then(err).then(json)
export const getLlmStatus = () => fetch(`${BASE_URL}/llm-status`).then(err).then(json)

export const postFeedback = (userId, action, note) =>
  fetch(`${BASE_URL}/feedback/${userId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action, note })
  }).then(err).then(json)

/**
 * Streams the narrative SSE for a user.
 * Detects [PROSECUTOR …] and [DEVIL'S ADVOCATE …] section headers.
 * onSection(name)  → called when a new section starts
 * onChunk(text)    → called for each text chunk
 * onError(msg)     → called if ERROR: prefix detected
 * onDone()         → called when [DONE] arrives
 * Returns the EventSource so caller can close it.
 */
export function streamNarrative(userId, { onSection, onChunk, onError, onDone } = {}) {
  const source = new EventSource(`${BASE_URL}/users/${userId}/narrative`)

  source.onmessage = ({ data }) => {
    if (data === '[DONE]') {
      source.close()
      onDone?.()
      return
    }
    if (data.startsWith('ERROR')) {
      onError?.(data.replace(/^ERROR[:\s]*/, ''))
      return
    }
    if (data.startsWith('[PROSECUTOR')) {
      onSection?.('prosecutor')
      return
    }
    if (data.startsWith("[DEVIL'S ADVOCATE")) {
      onSection?.('da')
      return
    }
    onChunk?.(data)
  }

  source.onerror = () => {
    source.close()
    onError?.('Connection lost. Make sure the backend is running.')
  }

  return source
}
