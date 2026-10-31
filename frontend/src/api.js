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
export const getBreachSimulation = userId => fetch(`${BASE_URL}/users/${userId}/breach-simulation`).then(err).then(json)
export const getClusterSummary = () => fetch(`${BASE_URL}/clusters/summary`).then(err).then(json)

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
export function streamNarrative(userId, { onSection, onChunk, onError, onDone, refresh = false } = {}) {
  const source = new EventSource(`${BASE_URL}/users/${userId}/narrative${refresh ? '?refresh=true' : ''}`)
  let currentSection = null  // track active section inside the SSE handler

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
      currentSection = 'prosecutor'
      onSection?.('prosecutor')
      return
    }
    if (data.startsWith("[DEVIL'S ADVOCATE")) {
      currentSection = 'da'
      onSection?.('da')
      return
    }
    // Pass section as second arg so caller can route without its own state read
    onChunk?.(data, currentSection)
  }

  source.onerror = () => {
    source.close()
    onError?.('Connection lost. Make sure the backend is running.')
  }

  return source
}

/**
 * Streams the inference SSE for a user (Pass 3: final verdict).
 * Collects all chunks and calls onChunk with each text piece.
 * onDone(rawText) is called when [DONE] arrives with the full raw JSON string.
 * Returns the EventSource so the caller can close it.
 */
export function streamInference(userId, { onChunk, onError, onDone } = {}) {
  const source = new EventSource(`${BASE_URL}/users/${userId}/inference`)
  const chunks = []

  source.onmessage = ({ data }) => {
    if (data === '[DONE]') {
      source.close()
      onDone?.(chunks.join(''))
      return
    }
    if (data.startsWith('ERROR')) {
      source.close()
      onError?.(data.replace(/^ERROR[:\s]*/, ''))
      return
    }
    if (data.startsWith('[INFERENCE')) return  // section header
    chunks.push(data)
    onChunk?.(data)
  }

  source.onerror = () => {
    source.close()
    onError?.('Connection lost. Make sure the backend is running.')
  }

  return source
}

/* ─── Phase 1: Schema Autopilot & Unified Schema API ─────── */

export const uploadSourceFile = (file) => {
  const formData = new FormData()
  formData.append('file', file)
  return fetch(`${BASE_URL}/api/sources`, {
    method: 'POST',
    body: formData,
  }).then(err).then(json)
}

export const registerSqlSource = (sqlConfig) => {
  const formData = new FormData()
  formData.append('sql_config', JSON.stringify(sqlConfig))
  return fetch(`${BASE_URL}/api/sources`, {
    method: 'POST',
    body: formData,
  }).then(err).then(json)
}

export const getSourceProfile = (sourceId) =>
  fetch(`${BASE_URL}/api/sources/${sourceId}/profile`).then(err).then(json)

export const proposeSourceMapping = (sourceId, targetRole = null, useLlm = true) =>
  fetch(`${BASE_URL}/api/sources/${sourceId}/propose-mapping`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target_role: targetRole, use_llm: useLlm }),
  }).then(err).then(json)

export const saveMappingProfile = (profileId, payload) =>
  fetch(`${BASE_URL}/api/mappings/${profileId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  }).then(err).then(json)

export const previewMapping = (profileId, payload) =>
  fetch(`${BASE_URL}/api/mappings/${profileId}/preview`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  }).then(err).then(json)

export const proposeUnifiedSchema = (draftId, sourceIds) =>
  fetch(`${BASE_URL}/api/drafts/${draftId}/unified-schema/propose`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ source_ids: sourceIds }),
  }).then(err).then(json)

export const getUnifiedSchema = (schemaId) =>
  fetch(`${BASE_URL}/api/unified-schema/${schemaId}`).then(err).then(json)

export const patchUnifiedSchema = (schemaId, ops) =>
  fetch(`${BASE_URL}/api/unified-schema/${schemaId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(ops),
  }).then(err).then(json)

export const deriveFieldFromText = (schemaId, prompt) =>
  fetch(`${BASE_URL}/api/unified-schema/${schemaId}/derive-from-text`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ prompt }),
  }).then(err).then(json)

export const undoUnifiedSchema = (schemaId) =>
  fetch(`${BASE_URL}/api/unified-schema/${schemaId}/undo`, { method: 'POST' }).then(err).then(json)

export const redoUnifiedSchema = (schemaId) =>
  fetch(`${BASE_URL}/api/unified-schema/${schemaId}/redo`, { method: 'POST' }).then(err).then(json)

export const resetUnifiedSchema = (schemaId) =>
  fetch(`${BASE_URL}/api/unified-schema/${schemaId}/reset`, { method: 'POST' }).then(err).then(json)

export const diffUnifiedSchema = (schemaId) =>
  fetch(`${BASE_URL}/api/unified-schema/${schemaId}/diff`).then(err).then(json)

export const previewUnifiedSchema = (schemaId, n = 20) =>
  fetch(`${BASE_URL}/api/unified-schema/${schemaId}/preview?n=${n}`).then(err).then(json)

export const createRun = (sourceIds, profileIds) =>
  fetch(`${BASE_URL}/api/runs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ source_ids: sourceIds, profile_ids: profileIds }),
  }).then(err).then(json)

// ── Feature 1b: Identity Resolution API ──────────────────────────────────────

export const getResolutionSummary = (runId = 'default') =>
  fetch(`${BASE_URL}/api/resolution/${runId}`).then(err).then(json)

export const getResolutionClusters = (runId = 'default') =>
  fetch(`${BASE_URL}/api/resolution/${runId}/clusters`).then(err).then(json)

export const getResolutionOrphans = (runId = 'default') =>
  fetch(`${BASE_URL}/api/resolution/${runId}/orphans`).then(err).then(json)

export const getResolutionLeavers = (runId = 'default') =>
  fetch(`${BASE_URL}/api/resolution/${runId}/leavers`).then(err).then(json)

export const getResolutionClassifications = (runId = 'default', classificationType = '') => {
  const url = classificationType
    ? `${BASE_URL}/api/resolution/${runId}/classifications?classification_type=${classificationType}`
    : `${BASE_URL}/api/resolution/${runId}/classifications`
  return fetch(url).then(err).then(json)
}

export const getResolutionReviewQueue = (runId = 'default') =>
  fetch(`${BASE_URL}/api/resolution/${runId}/review`).then(err).then(json)

export const decideReviewItem = (runId = 'default', itemId, action) =>
  fetch(`${BASE_URL}/api/resolution/${runId}/review/${itemId}/decide`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action }),
  }).then(err).then(json)

export const mergeIdentities = (runId = 'default', targetIdentityId, sourceIdentityId) =>
  fetch(`${BASE_URL}/api/resolution/${runId}/merge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target_identity_id: targetIdentityId, source_identity_id: sourceIdentityId }),
  }).then(err).then(json)

export const splitAccount = (runId = 'default', accountId) =>
  fetch(`${BASE_URL}/api/resolution/${runId}/split`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ account_id: accountId }),
  }).then(err).then(json)

export const triggerResolution = (runId = 'default') =>
  fetch(`${BASE_URL}/api/resolution/run`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ run_id: runId }),
  }).then(err).then(json)

