const BASE_URL = 'http://localhost:8000'

// POST /run-pipeline -> returns { status }.
export async function runPipeline() {
  const response = await fetch(`${BASE_URL}/run-pipeline`, { method: 'POST' })
  return response.json()
}

// GET /status -> returns the pipeline state dictionary.
export async function getStatus() {
  const response = await fetch(`${BASE_URL}/status`)
  return response.json()
}

// GET /users/risks -> returns an array of UserRiskProfile objects.
export async function getUserRisks() {
  const response = await fetch(`${BASE_URL}/users/risks`)
  return response.json()
}

// GET /users/{userId} -> returns a single UserRiskProfile.
export async function getUser(userId) {
  const response = await fetch(`${BASE_URL}/users/${userId}`)
  return response.json()
}

// POST /feedback/{userId} -> returns { status }.
export async function postFeedback(userId, action, note) {
  const response = await fetch(`${BASE_URL}/feedback/${userId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action, note })
  })
  return response.json()
}

// GET /org-anomalies -> returns an array of org anomaly summaries.
export async function getOrgAnomalies() {
  const response = await fetch(`${BASE_URL}/org-anomalies`)
  return response.json()
}

// GET /stats -> returns the dashboard stats dictionary.
export async function getStats() {
  const response = await fetch(`${BASE_URL}/stats`)
  return response.json()
}

// Opens EventSource on /users/{userId}/narrative and forwards SSE chunks to callbacks.
export function streamNarrative(userId, onChunk, onDone) {
  const source = new EventSource(`${BASE_URL}/users/${userId}/narrative`)

  source.onmessage = event => {
    if (event.data === '[DONE]') {
      source.close()
      onDone?.()
      return
    }
    onChunk?.(event.data)
  }

  source.onerror = () => {
    source.close()
  }

  return source
}
