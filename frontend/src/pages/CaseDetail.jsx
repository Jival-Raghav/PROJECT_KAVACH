import { useState, useEffect } from 'react'
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  CheckCircle,
  AlertTriangle,
  XCircle,
  FileText,
  Search,
  ExternalLink,
  ChevronRight,
  RefreshCw,
  Sliders,
  Scale,
  Clock,
  Sparkles,
  Info,
  Terminal,
  Database,
  Calendar,
  Layers,
  ArrowRight
} from 'lucide-react'

export default function CaseDetail({ currentUserId = 'USR00173', onSelectUser }) {
  const [selectedUid, setSelectedUid] = useState(currentUserId || 'USR00173')
  const [caseData, setCaseData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [activeEvidenceModal, setActiveEvidenceModal] = useState(null)
  const [recentCases, setRecentCases] = useState([])

  // Load available investigated cases
  useEffect(() => {
    fetch('/api/investigate/cases')
      .then(res => res.json())
      .then(data => {
        if (data.status === 'success' && data.cases) {
          setRecentCases(data.cases)
        }
      })
      .catch(() => {})
  }, [])

  // Fetch or run case investigation
  const loadCase = (userId) => {
    if (!userId) return
    setLoading(true)
    setError(null)
    fetch(`/api/investigate/${encodeURIComponent(userId)}/case`)
      .then(res => {
        if (!res.ok) throw new Error(`HTTP ${res.status}: Failed to load case dossier`)
        return res.json()
      })
      .then(data => {
        if (data.status === 'success' && data.case) {
          setCaseData(data.case)
          setSelectedUid(userId)
        } else {
          throw new Error('Malformed response payload')
        }
      })
      .catch(err => {
        setError(err.message)
      })
      .finally(() => {
        setLoading(false)
      })
  }

  const runFreshInvestigation = () => {
    if (!selectedUid) return
    setLoading(true)
    setError(null)
    fetch(`/api/investigate/${encodeURIComponent(selectedUid)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ run_id: 'default', use_llm: true }),
    })
      .then(res => {
        if (!res.ok) throw new Error(`HTTP ${res.status}: Investigation run failed`)
        return res.json()
      })
      .then(data => {
        if (data.status === 'success' && data.case) {
          setCaseData(data.case)
        }
      })
      .catch(err => {
        setError(err.message)
      })
      .finally(() => {
        setLoading(false)
      })
  }

  useEffect(() => {
    loadCase(selectedUid)
  }, [selectedUid])

  const findToolEvidence = (callId) => {
    if (!caseData || !caseData.tool_results) return null
    return caseData.tool_results.find(r => r.tool_call_id === callId)
  }

  const getVerdictStyle = (verdict) => {
    if (verdict === 'MITIGATED_BENIGN') {
      return {
        bg: 'rgba(16, 185, 129, 0.12)',
        border: 'rgba(16, 185, 129, 0.4)',
        color: '#10B981',
        icon: ShieldCheck,
        title: 'ALERT MITIGATED BY EVIDENCE',
        badgeClass: 'badge-normal',
      }
    }
    if (verdict === 'CONFIRMED_THREAT') {
      return {
        bg: 'rgba(239, 68, 68, 0.12)',
        border: 'rgba(239, 68, 68, 0.4)',
        color: '#EF4444',
        icon: ShieldAlert,
        title: 'CONFIRMED SECURITY INCIDENT',
        badgeClass: 'badge-critical',
      }
    }
    return {
      bg: 'rgba(245, 158, 11, 0.12)',
      border: 'rgba(245, 158, 11, 0.4)',
      color: '#F59E0B',
      icon: AlertTriangle,
      title: 'REQUIRES SOC HUMAN REVIEW',
      badgeClass: 'badge-review',
    }
  }

  const vStyle = caseData ? getVerdictStyle(caseData.verdict) : null
  const VIcon = vStyle ? vStyle.icon : Shield

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

      {/* ── Top Bar & Case Selector ── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Scale size={20} color="#00E5FF" />
            <h2 style={{ fontSize: 18, fontWeight: 700, margin: 0 }}>
              Adversarial Case Investigation & Remediation Co-Pilot
            </h2>
            <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 4, background: 'rgba(0,229,255,0.1)', color: '#00E5FF', border: '1px solid rgba(0,229,255,0.3)', fontWeight: 600 }}>
              3-PASS ADVERSARIAL
            </span>
          </div>
          <p style={{ fontSize: 12, color: 'var(--text-secondary)', margin: '4px 0 0 0' }}>
            Prosecutor formulation $\to$ Devil's Advocate tool verification $\to$ Binding CISO Adjudication
          </p>
        </div>

        {/* User Search & Re-Run */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{ position: 'relative' }}>
            <input
              type="text"
              placeholder="Enter User Key (e.g. USR00173, U_ONCALL_NIGHT)..."
              value={selectedUid}
              onChange={(e) => setSelectedUid(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && loadCase(selectedUid)}
              style={{
                background: 'var(--surface-high)',
                border: '1px solid var(--border)',
                color: 'var(--text-primary)',
                padding: '6px 12px 6px 30px',
                borderRadius: 4,
                fontSize: 12,
                width: 260,
                outline: 'none',
              }}
            />
            <Search size={14} style={{ position: 'absolute', left: 9, top: 9, color: 'var(--text-muted)' }} />
          </div>

          <button
            onClick={() => loadCase(selectedUid)}
            disabled={loading}
            className="btn-secondary"
            style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, padding: '6px 12px' }}
          >
            <RefreshCw size={13} className={loading ? 'spin' : ''} />
            {loading ? 'Analyzing...' : 'Fetch Dossier'}
          </button>

          <button
            onClick={runFreshInvestigation}
            disabled={loading}
            className="btn-primary"
            style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, padding: '6px 14px' }}
          >
            <Sparkles size={13} />
            Run Full Co-Pilot
          </button>
        </div>
      </div>

      {error && (
        <div style={{ padding: '10px 14px', borderRadius: 6, background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', color: '#EF4444', fontSize: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
          <XCircle size={15} />
          <span>{error}</span>
        </div>
      )}

      {caseData && (
        <>
          {/* ── Verdict Banner & Metrics Strip ── */}
          <div style={{
            background: vStyle.bg,
            border: `1px solid ${vStyle.border}`,
            borderRadius: 8,
            padding: '16px 20px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: 16,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
              <div style={{
                width: 44,
                height: 44,
                borderRadius: '50%',
                background: 'var(--surface-base)',
                border: `2px solid ${vStyle.color}`,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: vStyle.color,
              }}>
                <VIcon size={22} />
              </div>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.08em', color: vStyle.color }}>
                    {vStyle.title}
                  </span>
                  <span className={vStyle.badgeClass} style={{ fontSize: 10, padding: '1px 6px' }}>
                    {caseData.verdict}
                  </span>
                </div>
                <div style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)', marginTop: 2 }}>
                  Case Dossier: {caseData.user_id}
                </div>
              </div>
            </div>

            {/* Metrics: Doubt Score & Severity Transition */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
              {/* Doubt Gauge */}
              <div style={{ textAlign: 'right' }}>
                <div style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-secondary)', letterSpacing: '0.05em' }}>
                  Defense Doubt Score
                </div>
                <div style={{ fontSize: 20, fontWeight: 800, color: caseData.doubt_score >= 0.75 ? '#10B981' : (caseData.doubt_score >= 0.40 ? '#F59E0B' : '#EF4444') }}>
                  {(caseData.doubt_score * 100).toFixed(0)}%
                </div>
                <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                  {caseData.doubt_score >= 0.75 ? 'Strong Exoneration' : (caseData.doubt_score >= 0.40 ? 'Moderate Doubts' : 'No Valid Mitigators')}
                </div>
              </div>

              <div style={{ width: 1, height: 38, background: 'var(--border)' }} />

              {/* Severity Transition */}
              <div>
                <div style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-secondary)', letterSpacing: '0.05em' }}>
                  Adjusted Severity
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 3 }}>
                  <span style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>
                    {caseData.severity}
                  </span>
                </div>
                <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                  Binding Final Level
                </div>
              </div>
            </div>
          </div>

          {/* ── Split-Screen Adversarial Arena ── */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>

            {/* Left Column: The Prosecution (Pass 1) */}
            <div className="card" style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border)', paddingBottom: 10 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <ShieldAlert size={16} color="#EF4444" />
                  <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Pass 1: Security Prosecution ({caseData.claims?.length || 0} Claims)
                  </span>
                </div>
                <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>Adversarial Charge Sheet</span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {caseData.claims?.map((claim, idx) => (
                  <div
                    key={claim.claim_id || idx}
                    style={{
                      background: 'var(--surface-mid)',
                      border: '1px solid var(--border)',
                      borderLeft: claim.hard_rule ? '4px solid #EF4444' : '4px solid #F59E0B',
                      borderRadius: 4,
                      padding: 12,
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 6 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <span className="mono" style={{ fontSize: 11, fontWeight: 700, color: '#00E5FF' }}>
                          {claim.claim_id.toUpperCase()}
                        </span>
                        <span style={{ fontSize: 10, textTransform: 'uppercase', padding: '1px 6px', borderRadius: 3, background: 'var(--surface-high)', color: 'var(--text-secondary)' }}>
                          {claim.type}
                        </span>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        {claim.hard_rule && (
                          <span style={{ fontSize: 9, fontWeight: 700, padding: '1px 5px', borderRadius: 3, background: 'rgba(239,68,68,0.15)', color: '#EF4444', border: '1px solid rgba(239,68,68,0.4)' }}>
                            HARD RULE
                          </span>
                        )}
                        <span className={claim.severity === 'critical' ? 'badge-critical' : 'badge-review'} style={{ fontSize: 9, padding: '1px 5px' }}>
                          {claim.severity}
                        </span>
                      </div>
                    </div>

                    <div style={{ fontSize: 12, color: 'var(--text-primary)', lineHeight: 1.4, fontWeight: 500 }}>
                      {claim.statement}
                    </div>

                    {claim.event_ids?.length > 0 && (
                      <div style={{ marginTop: 8, fontSize: 10, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 4 }}>
                        <span>Associated Events:</span>
                        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                          {claim.event_ids.map(eid => (
                            <span key={eid} className="mono" style={{ padding: '1px 4px', background: 'var(--surface-base)', borderRadius: 2 }}>
                              {eid}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Right Column: The Devil's Advocate (Pass 2) */}
            <div className="card" style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border)', paddingBottom: 10 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Scale size={16} color="#00E5FF" />
                  <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Pass 2: Devil's Advocate Rebuttal ({caseData.rebuttals?.length || 0} Evaluations)
                  </span>
                </div>
                <span style={{ fontSize: 10, color: '#00E5FF', fontWeight: 600 }}>Evidence-Grounded Defense</span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {caseData.rebuttals?.map((reb, idx) => {
                  const isRefuted = reb.status === 'refuted'
                  const isWeakened = reb.status === 'weakened'
                  const isStands = reb.status === 'stands'
                  const borderColor = isRefuted ? '#10B981' : (isWeakened ? '#00E5FF' : (isStands ? '#EF4444' : 'var(--border)'))

                  return (
                    <div
                      key={reb.claim_id || idx}
                      style={{
                        background: 'var(--surface-mid)',
                        border: '1px solid var(--border)',
                        borderLeft: `4px solid ${borderColor}`,
                        borderRadius: 4,
                        padding: 12,
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                        <span className="mono" style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)' }}>
                          RE: {reb.claim_id.toUpperCase()}
                        </span>
                        <span style={{
                          fontSize: 10, fontWeight: 700, textTransform: 'uppercase', padding: '2px 8px', borderRadius: 4,
                          background: isRefuted ? 'rgba(16,185,129,0.15)' : (isWeakened ? 'rgba(0,229,255,0.15)' : 'rgba(239,68,68,0.15)'),
                          color: borderColor,
                          border: `1px solid ${borderColor}`,
                        }}>
                          {reb.status}
                        </span>
                      </div>

                      <div style={{ fontSize: 12, color: 'var(--text-primary)', lineHeight: 1.4 }}>
                        {reb.rationale}
                      </div>

                      {/* Cited Tool Call Badges */}
                      {reb.cited_tool_call_ids?.length > 0 && (
                        <div style={{ marginTop: 10, display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                          <span style={{ fontSize: 10, color: 'var(--text-secondary)' }}>Cited Evidence:</span>
                          {reb.cited_tool_call_ids.map(cid => {
                            const ev = findToolEvidence(cid)
                            return (
                              <button
                                key={cid}
                                onClick={() => setActiveEvidenceModal(ev)}
                                style={{
                                  background: 'rgba(0,229,255,0.1)',
                                  border: '1px solid rgba(0,229,255,0.3)',
                                  color: '#00E5FF',
                                  fontSize: 10,
                                  fontWeight: 600,
                                  padding: '2px 8px',
                                  borderRadius: 4,
                                  cursor: 'pointer',
                                  display: 'flex',
                                  alignItems: 'center',
                                  gap: 4,
                                }}
                                title="Click to view raw evidence rows"
                              >
                                <Terminal size={10} />
                                <span>{ev ? ev.tool : cid}</span>
                                <ExternalLink size={10} />
                              </button>
                            )
                          })}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>

          </div>

          {/* ── Pass 3: CISO Adjudication & Concrete Remediation ── */}
          <div className="card" style={{ padding: 18, display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border)', paddingBottom: 10 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <CheckCircle size={16} color="#10B981" />
                <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Pass 3: Binding CISO Adjudication & Remediation Synthesis
                </span>
              </div>
              <span className={vStyle.badgeClass} style={{ fontSize: 10 }}>
                {caseData.verdict}
              </span>
            </div>

            {/* Executive Summary */}
            <div style={{ background: 'var(--surface-mid)', border: '1px solid var(--border)', borderRadius: 6, padding: 14 }}>
              <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-secondary)', marginBottom: 6 }}>
                Executive Assessment
              </div>
              <p style={{ fontSize: 13, color: 'var(--text-primary)', lineHeight: 1.5, margin: 0 }}>
                {caseData.summary}
              </p>
            </div>

            {/* Chronological Corroborated Timeline */}
            {caseData.timeline?.length > 0 && (
              <div>
                <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-secondary)', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Clock size={12} />
                  Corroborated Telemetry & Context Timeline
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {caseData.timeline.map((item, idx) => (
                    <div
                      key={idx}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 12,
                        padding: '6px 10px',
                        background: 'var(--surface-high)',
                        borderRadius: 4,
                        fontSize: 11,
                      }}
                    >
                      <span className="mono" style={{ color: 'var(--text-muted)', width: 140, flexShrink: 0 }}>
                        {item.timestamp}
                      </span>
                      <span style={{
                        padding: '1px 6px', borderRadius: 3, fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
                        background: item.type === 'alert' ? 'rgba(239,68,68,0.15)' : (item.type === 'mitigation' ? 'rgba(16,185,129,0.15)' : 'var(--surface-mid)'),
                        color: item.type === 'alert' ? '#EF4444' : (item.type === 'mitigation' ? '#10B981' : 'var(--text-secondary)'),
                        width: 75, textAlign: 'center', flexShrink: 0,
                      }}>
                        {item.type}
                      </span>
                      <span style={{ color: 'var(--text-primary)' }}>
                        {item.description}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Concrete Remediation Steps */}
            <div>
              <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-secondary)', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
                <Terminal size={12} />
                Actionable Remediation Directives (Dry-Run Only)
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 10 }}>
                {caseData.remediation_steps?.map((step, idx) => (
                  <div
                    key={idx}
                    style={{
                      background: 'var(--surface-mid)',
                      border: '1px solid var(--border)',
                      borderRadius: 6,
                      padding: 12,
                      display: 'flex',
                      flexDirection: 'column',
                      gap: 6,
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{
                        fontSize: 10, fontWeight: 700, textTransform: 'uppercase', padding: '2px 6px', borderRadius: 3,
                        background: step.action === 'NO_ACTION' ? 'rgba(16,185,129,0.15)' : 'rgba(239,68,68,0.15)',
                        color: step.action === 'NO_ACTION' ? '#10B981' : '#EF4444',
                      }}>
                        {step.action}
                      </span>
                      <span className="mono" style={{ fontSize: 11, color: '#00E5FF' }}>
                        {step.target}
                      </span>
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                      {step.rationale}
                    </div>
                  </div>
                ))}
              </div>
            </div>

          </div>
        </>
      )}

      {/* ── Evidence Inspection Drawer / Modal ── */}
      {activeEvidenceModal && (
        <div style={{
          position: 'fixed',
          top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.7)',
          backdropFilter: 'blur(3px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
          padding: 20,
        }}>
          <div className="card" style={{ maxWidth: 640, width: '100%', padding: 20, display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border)', paddingBottom: 10 }}>
              <div>
                <div style={{ fontSize: 11, color: '#00E5FF', textTransform: 'uppercase', fontWeight: 700 }}>
                  Tool Evidence Dossier
                </div>
                <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)', marginTop: 2 }}>
                  {activeEvidenceModal.tool} ({activeEvidenceModal.tool_call_id})
                </div>
              </div>
              <button
                onClick={() => setActiveEvidenceModal(null)}
                className="btn-icon"
                style={{ cursor: 'pointer' }}
              >
                ✕
              </button>
            </div>

            <div>
              <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 6 }}>
                Execution Message:
              </div>
              <div style={{ fontSize: 12, padding: 10, background: 'var(--surface-mid)', borderRadius: 4, color: activeEvidenceModal.result ? '#10B981' : '#EF4444' }}>
                {activeEvidenceModal.message}
              </div>
            </div>

            <div>
              <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 6 }}>
                Verified Telemetry & Context Rows:
              </div>
              <pre className="mono" style={{
                background: 'var(--surface-base)',
                border: '1px solid var(--border)',
                padding: 12,
                borderRadius: 4,
                fontSize: 11,
                maxHeight: 220,
                overflowY: 'auto',
                color: 'var(--text-primary)',
              }}>
                {JSON.stringify(activeEvidenceModal.evidence_rows || [], null, 2)}
              </pre>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button
                onClick={() => setActiveEvidenceModal(null)}
                className="btn-primary"
                style={{ fontSize: 12, padding: '6px 16px' }}
              >
                Dismiss Evidence
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  )
}
