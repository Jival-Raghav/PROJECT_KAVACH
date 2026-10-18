import { useEffect, useState } from 'react'
import {
  AlertTriangle,
  ArrowRight,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock,
  ExternalLink,
  Filter,
  GitBranch,
  Layers,
  Link as LinkIcon,
  Loader2,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  Split,
  Trash2,
  User,
  UserCheck,
  UserMinus,
  Users,
  X,
  XCircle,
} from 'lucide-react'
import {
  decideReviewItem,
  getResolutionClassifications,
  getResolutionClusters,
  getResolutionLeavers,
  getResolutionOrphans,
  getResolutionReviewQueue,
  getResolutionSummary,
  mergeIdentities,
  splitAccount,
  triggerResolution,
} from '../api'

export default function ResolutionView({ runId = 'default' }) {
  const [loading, setLoading] = useState(true)
  const [running, setRunning] = useState(false)
  const [summary, setSummary] = useState(null)
  const [activeSubTab, setActiveSubTab] = useState('clusters') // clusters | leavers | orphans | review | all
  const [searchQuery, setSearchQuery] = useState('')

  // Data states
  const [clusters, setClusters] = useState([])
  const [leavers, setLeavers] = useState([])
  const [orphans, setOrphans] = useState([])
  const [reviewQueue, setReviewQueue] = useState([])
  const [classifications, setClassifications] = useState([])
  const [classFilter, setClassFilter] = useState('all')

  // UI interaction states
  const [expandedClusterId, setExpandedClusterId] = useState(null)
  const [actionMessage, setActionMessage] = useState(null)
  const [mergeModalOpen, setMergeModalOpen] = useState(false)
  const [targetMergeId, setTargetMergeId] = useState('')
  const [sourceMergeId, setSourceMergeId] = useState('')

  const loadData = async () => {
    try {
      setLoading(true)
      const [sumRes, clusRes, leavRes, orphRes, revRes, allRes] = await Promise.allSettled([
        getResolutionSummary(runId),
        getResolutionClusters(runId),
        getResolutionLeavers(runId),
        getResolutionOrphans(runId),
        getResolutionReviewQueue(runId),
        getResolutionClassifications(runId),
      ])

      if (sumRes.status === 'fulfilled') setSummary(sumRes.value?.metrics || {})
      if (clusRes.status === 'fulfilled') setClusters(clusRes.value || [])
      if (leavRes.status === 'fulfilled') setLeavers(leavRes.value || [])
      if (orphRes.status === 'fulfilled') setOrphans(orphRes.value || [])
      if (revRes.status === 'fulfilled') setReviewQueue(revRes.value || [])
      if (allRes.status === 'fulfilled') setClassifications(allRes.value || [])
    } catch (e) {
      console.error('Failed to load resolution data:', e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadData()
  }, [runId])

  const handleTriggerRun = async () => {
    try {
      setRunning(true)
      await triggerResolution(runId)
      setActionMessage({ type: 'success', text: 'Identity resolution completed successfully.' })
      await loadData()
    } catch (e) {
      setActionMessage({ type: 'error', text: `Resolution failed: ${e.message}` })
    } finally {
      setRunning(false)
    }
  }

  const handleReviewDecision = async (itemId, action) => {
    try {
      await decideReviewItem(runId, itemId, action)
      setReviewQueue(prev => prev.filter(item => item.item_id !== itemId))
      setActionMessage({
        type: 'success',
        text: action === 'accept' ? 'Match accepted and identity linked.' : 'Match rejected.',
      })
      await loadData()
    } catch (e) {
      setActionMessage({ type: 'error', text: `Review action failed: ${e.message}` })
    }
  }

  const handleSplit = async (accountId) => {
    if (!window.confirm(`Detach account '${accountId}' into its own standalone golden identity?`)) return
    try {
      const res = await splitAccount(runId, accountId)
      setActionMessage({ type: 'success', text: `Account split into new identity '${res.new_identity_id}'.` })
      await loadData()
    } catch (e) {
      setActionMessage({ type: 'error', text: `Split failed: ${e.message}` })
    }
  }

  const handleMergeSubmit = async () => {
    if (!targetMergeId || !sourceMergeId) return
    try {
      await mergeIdentities(runId, targetMergeId, sourceMergeId)
      setMergeModalOpen(false)
      setTargetMergeId('')
      setSourceMergeId('')
      setActionMessage({ type: 'success', text: `Merged '${sourceMergeId}' into '${targetMergeId}'.` })
      await loadData()
    } catch (e) {
      setActionMessage({ type: 'error', text: `Merge rejected: ${e.message}` })
    }
  }

  // Filtered clusters
  const filteredClusters = clusters.filter(c => {
    if (!searchQuery) return true
    const q = searchQuery.toLowerCase()
    return (
      (c.canonical_name && c.canonical_name.toLowerCase().includes(q)) ||
      (c.identity_id && c.identity_id.toLowerCase().includes(q)) ||
      (c.employee_id && c.employee_id.toLowerCase().includes(q)) ||
      (c.primary_email && c.primary_email.toLowerCase().includes(q)) ||
      (c.department && c.department.toLowerCase().includes(q)) ||
      c.accounts?.some(a => a.username.toLowerCase().includes(q) || a.system.toLowerCase().includes(q))
    )
  })

  // Filtered classifications
  const filteredClassifications = classifications.filter(cl => {
    if (classFilter !== 'all' && cl.classification !== classFilter) return false
    if (!searchQuery) return true
    const q = searchQuery.toLowerCase()
    return (
      cl.username.toLowerCase().includes(q) ||
      cl.system.toLowerCase().includes(q) ||
      (cl.owner && cl.owner.toLowerCase().includes(q))
    )
  })

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden', background: '#090D16' }}>
      {/* ── Top Header Bar ── */}
      <div style={{
        padding: '16px 24px',
        borderBottom: '1px solid #1E293B',
        background: '#0D1526',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexShrink: 0,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{
            width: 36, height: 36, borderRadius: 8,
            background: 'var(--accent-subtle)',
            border: '1px solid var(--accent-border)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <GitBranch size={20} color="var(--accent)" />
          </div>
          <div>
            <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
              Identity Resolution Engine
              <span style={{
                fontSize: 11, padding: '2px 8px', borderRadius: 999,
                background: 'var(--accent-subtle)', color: 'var(--accent)', border: '1px solid var(--accent-border)',
                fontWeight: 600,
              }}>
                Feature 1b · Constrained Union-Find
              </span>
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
              Deterministic &amp; fuzzy graph reconciliation · Zero cross-employee merges · Credential sprawl detector
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <button
            onClick={() => setMergeModalOpen(true)}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              background: 'var(--surface-mid)', color: 'var(--text-primary)', border: '1px solid var(--border)',
              borderRadius: 6, padding: '7px 14px', fontSize: 12, fontWeight: 600, cursor: 'pointer',
            }}
          >
            <LinkIcon size={14} color="var(--accent)" />
            Manual Merge
          </button>

          <button
            onClick={handleTriggerRun}
            disabled={running}
            className="btn-primary"
            style={{
              display: 'flex', alignItems: 'center', gap: 8,
              borderRadius: 6, padding: '7px 16px', fontSize: 12, fontWeight: 700, cursor: running ? 'not-allowed' : 'pointer',
            }}
          >
            {running ? <Loader2 size={15} className="spin" /> : <RefreshCw size={15} />}
            {running ? 'Resolving...' : 'Re-Run Resolution'}
          </button>
        </div>
      </div>

      {/* ── Action Alert Banner ── */}
      {actionMessage && (
        <div style={{
          padding: '10px 24px',
          background: actionMessage.type === 'success' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
          borderBottom: `1px solid ${actionMessage.type === 'success' ? '#10B981' : '#EF4444'}`,
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          fontSize: 12, color: actionMessage.type === 'success' ? '#34D399' : '#F87171',
        }}>
          <span>{actionMessage.text}</span>
          <button
            onClick={() => setActionMessage(null)}
            style={{ background: 'transparent', border: 'none', color: 'inherit', cursor: 'pointer' }}
          >
            <X size={14} />
          </button>
        </div>
      )}

      {/* ── KPI Command Metrics Grid ── */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(6, 1fr)',
        gap: 12,
        padding: '16px 24px',
        borderBottom: '1px solid #1E293B',
        background: '#090D16',
        flexShrink: 0,
      }}>
        {/* KPI 1 */}
        <div style={{
          background: '#0D1526', border: '1px solid #1E293B', borderRadius: 8, padding: '12px 16px',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: '#94A3B8', fontSize: 11, fontWeight: 600 }}>
            <span>GOLDEN IDENTITIES</span>
            <Users size={14} color="#00E5FF" />
          </div>
          <div style={{ fontSize: 22, fontWeight: 800, color: '#F8FAFC', marginTop: 4 }}>
            {summary?.golden_identities_count ?? '-'}
          </div>
          <div style={{ fontSize: 11, color: '#64748B', marginTop: 2 }}>
            Unified person anchors
          </div>
        </div>

        {/* KPI 2 */}
        <div style={{
          background: '#0D1526', border: '1px solid #1E293B', borderRadius: 8, padding: '12px 16px',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: '#94A3B8', fontSize: 11, fontWeight: 600 }}>
            <span>ACCOUNTS LINKED</span>
            <CheckCircle2 size={14} color="#6366F1" />
          </div>
          <div style={{ fontSize: 22, fontWeight: 800, color: '#F8FAFC', marginTop: 4 }}>
            {summary?.account_links_count ?? '-'}
          </div>
          <div style={{ fontSize: 11, color: '#64748B', marginTop: 2 }}>
            Across all systems
          </div>
        </div>

        {/* KPI 3 (LEAVER ACTIVE - CRITICAL) */}
        <div style={{
          background: summary?.leaver_active_count > 0 ? 'rgba(239, 68, 68, 0.08)' : '#0D1526',
          border: `1px solid ${summary?.leaver_active_count > 0 ? '#EF4444' : '#1E293B'}`,
          borderRadius: 8, padding: '12px 16px',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: '#EF4444', fontSize: 11, fontWeight: 700 }}>
            <span>LEAVER-ACTIVE</span>
            <ShieldAlert size={14} color="#EF4444" />
          </div>
          <div style={{ fontSize: 22, fontWeight: 800, color: '#EF4444', marginTop: 4, display: 'flex', alignItems: 'center', gap: 6 }}>
            {summary?.leaver_active_count ?? 0}
            {summary?.leaver_active_count > 0 && (
              <span style={{ fontSize: 10, padding: '2px 6px', background: '#EF4444', color: '#090D16', borderRadius: 4, fontWeight: 800 }}>
                CRITICAL
              </span>
            )}
          </div>
          <div style={{ fontSize: 11, color: '#EF4444', marginTop: 2 }}>
            Terminated yet active!
          </div>
        </div>

        {/* KPI 4 */}
        <div style={{
          background: '#0D1526', border: '1px solid #1E293B', borderRadius: 8, padding: '12px 16px',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: '#F59E0B', fontSize: 11, fontWeight: 600 }}>
            <span>ORPHAN ACCOUNTS</span>
            <UserMinus size={14} color="#F59E0B" />
          </div>
          <div style={{ fontSize: 22, fontWeight: 800, color: '#F59E0B', marginTop: 4 }}>
            {summary?.orphaned_count ?? 0}
          </div>
          <div style={{ fontSize: 11, color: '#64748B', marginTop: 2 }}>
            No HR identity match
          </div>
        </div>

        {/* KPI 5 */}
        <div style={{
          background: '#0D1526', border: '1px solid #1E293B', borderRadius: 8, padding: '12px 16px',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: '#A855F7', fontSize: 11, fontWeight: 600 }}>
            <span>DORMANT</span>
            <Clock size={14} color="#A855F7" />
          </div>
          <div style={{ fontSize: 22, fontWeight: 800, color: '#F8FAFC', marginTop: 4 }}>
            {summary?.dormant_count ?? 0}
          </div>
          <div style={{ fontSize: 11, color: '#64748B', marginTop: 2 }}>
            &gt; 90 days inactive
          </div>
        </div>

        {/* KPI 6 */}
        <div style={{
          background: '#0D1526', border: '1px solid #1E293B', borderRadius: 8, padding: '12px 16px',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: '#3B82F6', fontSize: 11, fontWeight: 600 }}>
            <span>REVIEW QUEUE</span>
            <AlertTriangle size={14} color="#3B82F6" />
          </div>
          <div style={{ fontSize: 22, fontWeight: 800, color: '#F8FAFC', marginTop: 4 }}>
            {summary?.review_queue_count ?? 0}
          </div>
          <div style={{ fontSize: 11, color: '#64748B', marginTop: 2 }}>
            0.70 – 0.90 band matches
          </div>
        </div>
      </div>

      {/* ── Sub Navigation Tabs & Filter Bar ── */}
      <div style={{
        padding: '12px 24px',
        borderBottom: '1px solid #1E293B',
        background: '#0D1526',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexShrink: 0,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          {[
            { id: 'clusters', label: `Golden Clusters (${clusters.length})` },
            { id: 'leavers', label: `Leaver-Active Alerts (${leavers.length})`, alert: leavers.length > 0 },
            { id: 'orphans', label: `Orphan Accounts (${orphans.length})` },
            { id: 'review', label: `Review Queue (${reviewQueue.length})` },
            { id: 'all', label: `All Classifications (${classifications.length})` },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveSubTab(tab.id)}
              style={{
                padding: '6px 14px',
                borderRadius: 6,
                fontSize: 12,
                fontWeight: 600,
                cursor: 'pointer',
                border: '1px solid',
                borderColor: activeSubTab === tab.id ? 'var(--accent)' : 'transparent',
                background: activeSubTab === tab.id ? 'var(--accent-subtle)' : 'transparent',
                color: activeSubTab === tab.id ? 'var(--accent)' : (tab.alert ? 'var(--c-critical)' : 'var(--text-secondary)'),
                display: 'flex', alignItems: 'center', gap: 6,
              }}
            >
              {tab.label}
              {tab.alert && <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--c-critical)' }} />}
            </button>
          ))}
        </div>

        {/* Search */}
        <div style={{ position: 'relative', width: 280 }}>
          <Search size={14} color="#64748B" style={{ position: 'absolute', left: 10, top: 9 }} />
          <input
            type="text"
            placeholder="Search identities, usernames, accounts..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            style={{
              width: '100%',
              padding: '6px 10px 6px 32px',
              fontSize: 12,
              background: '#090D16',
              border: '1px solid #1E293B',
              borderRadius: 6,
              color: '#F8FAFC',
              outline: 'none',
            }}
          />
        </div>
      </div>

      {/* ── Main Tab Content Body ── */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '20px 24px' }}>
        {loading ? (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', gap: 12 }}>
            <Loader2 size={32} className="spin" color="#00E5FF" />
            <div style={{ fontSize: 13, color: '#94A3B8' }}>Loading identity graph &amp; cluster topology...</div>
          </div>
        ) : (
          <>
            {/* ══ SUB-TAB 1: GOLDEN CLUSTERS ══ */}
            {activeSubTab === 'clusters' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {filteredClusters.length === 0 ? (
                  <div style={{ textAlign: 'center', padding: 48, color: '#64748B', fontSize: 13 }}>
                    No golden identity clusters matched your criteria.
                  </div>
                ) : (
                  filteredClusters.map(cluster => {
                    const isExpanded = expandedClusterId === cluster.identity_id
                    return (
                      <div
                        key={cluster.identity_id}
                        style={{
                          background: '#0D1526',
                          border: '1px solid #1E293B',
                          borderRadius: 8,
                          overflow: 'hidden',
                          transition: 'border-color 0.15s ease',
                        }}
                      >
                        {/* Cluster Header */}
                        <div
                          onClick={() => setExpandedClusterId(isExpanded ? null : cluster.identity_id)}
                          style={{
                            padding: '14px 18px',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            cursor: 'pointer',
                            background: isExpanded ? 'rgba(0, 229, 255, 0.04)' : 'transparent',
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                            {isExpanded ? <ChevronDown size={16} color="#00E5FF" /> : <ChevronRight size={16} color="#64748B" />}
                            <div style={{
                              width: 32, height: 32, borderRadius: '50%',
                              background: '#1E293B', display: 'flex', alignItems: 'center', justifyContent: 'center',
                              fontWeight: 700, fontSize: 12, color: '#00E5FF',
                            }}>
                              {cluster.canonical_name?.substring(0, 2).toUpperCase()}
                            </div>
                            <div>
                              <div style={{ fontSize: 14, fontWeight: 700, color: '#F8FAFC', display: 'flex', alignItems: 'center', gap: 8 }}>
                                {cluster.canonical_name}
                                {cluster.employee_id && (
                                  <span style={{ fontSize: 11, padding: '1px 6px', background: '#1E293B', color: '#94A3B8', borderRadius: 4 }}>
                                    EMP: {cluster.employee_id}
                                  </span>
                                )}
                                <span style={{
                                  fontSize: 10, padding: '1px 6px', borderRadius: 4,
                                  background: cluster.employment_status === 'terminated' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                                  color: cluster.employment_status === 'terminated' ? '#EF4444' : '#10B981',
                                  fontWeight: 600,
                                }}>
                                  {cluster.employment_status?.toUpperCase() || 'ACTIVE'}
                                </span>
                              </div>
                              <div style={{ fontSize: 12, color: '#64748B', marginTop: 2, display: 'flex', gap: 12 }}>
                                <span>{cluster.primary_email || 'No primary email'}</span>
                                {cluster.department && <span>· Dept: {cluster.department}</span>}
                                {cluster.job_title && <span>· {cluster.job_title}</span>}
                              </div>
                            </div>
                          </div>

                          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                            {/* Account count chip */}
                            <span style={{
                              fontSize: 11, padding: '3px 10px', borderRadius: 999,
                              background: 'rgba(99, 102, 241, 0.15)', color: '#818CF8', border: '1px solid rgba(99, 102, 241, 0.3)',
                              fontWeight: 600,
                            }}>
                              {cluster.cluster_size || cluster.accounts?.length || 0} Linked Accounts
                            </span>

                            {/* Confidence Badge */}
                            <span style={{
                              fontSize: 11, padding: '3px 8px', borderRadius: 4,
                              background: cluster.confidence >= 0.95 ? 'rgba(16, 185, 129, 0.12)' : 'rgba(245, 158, 11, 0.12)',
                              color: cluster.confidence >= 0.95 ? '#34D399' : '#FBBF24',
                              fontWeight: 700,
                            }}>
                              {Math.round(cluster.confidence * 100)}% Conf
                            </span>
                          </div>
                        </div>

                        {/* Expanded Linked Accounts Table */}
                        {isExpanded && (
                          <div style={{ padding: '0 18px 18px 18px', borderTop: '1px solid #1E293B', background: '#090D16' }}>
                            <div style={{ fontSize: 11, fontWeight: 700, color: '#94A3B8', padding: '12px 0 8px 0', textTransform: 'uppercase' }}>
                              Linked System Accounts &amp; Resolution Evidence
                            </div>

                            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                              {cluster.accounts?.map(acc => (
                                <div
                                  key={acc.account_id}
                                  style={{
                                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                                    background: '#0D1526', border: '1px solid #1E293B', borderRadius: 6,
                                    padding: '10px 14px',
                                  }}
                                >
                                  <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                                    <span style={{
                                      fontSize: 11, padding: '2px 8px', borderRadius: 4,
                                      background: '#1E293B', color: '#00E5FF', fontWeight: 700, textTransform: 'uppercase',
                                    }}>
                                      {acc.system}
                                    </span>
                                    <div>
                                      <div style={{ fontSize: 13, fontWeight: 600, color: '#F8FAFC' }}>
                                        {acc.username}
                                        <span style={{ fontSize: 11, color: '#64748B', marginLeft: 8 }}>({acc.account_id})</span>
                                      </div>
                                      <div style={{ fontSize: 11, color: '#94A3B8', marginTop: 2, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                                        {acc.reasons?.map((r, ri) => (
                                          <span key={ri} style={{
                                            background: 'rgba(0, 229, 255, 0.08)', color: '#00E5FF',
                                            padding: '1px 6px', borderRadius: 3, fontSize: 10,
                                          }}>
                                            ✓ {r}
                                          </span>
                                        ))}
                                      </div>
                                    </div>
                                  </div>

                                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                                    <span style={{ fontSize: 11, color: '#10B981', fontWeight: 600 }}>
                                      {Math.round(acc.confidence * 100)}% Match
                                    </span>
                                    <button
                                      onClick={(e) => {
                                        e.stopPropagation()
                                        handleSplit(acc.account_id)
                                      }}
                                      title="Detach account into separate golden identity"
                                      style={{
                                        display: 'flex', alignItems: 'center', gap: 4,
                                        background: '#1E293B', color: '#F87171', border: '1px solid #334155',
                                        borderRadius: 4, padding: '4px 8px', fontSize: 11, cursor: 'pointer',
                                      }}
                                    >
                                      <Split size={12} />
                                      Split
                                    </button>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )
                  })
                )}
              </div>
            )}

            {/* ══ SUB-TAB 2: LEAVER-ACTIVE ALERTS ══ */}
            {activeSubTab === 'leavers' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div style={{
                  padding: '12px 16px', borderRadius: 6, background: 'rgba(239, 68, 68, 0.1)',
                  border: '1px solid rgba(239, 68, 68, 0.3)', color: '#F87171', fontSize: 12,
                }}>
                  <strong>High Severity Security Risk:</strong> The following accounts belong to employees whose HR records indicate they have been terminated, yet their credentials remain active or recent login activity was detected.
                </div>

                <div style={{ background: '#0D1526', border: '1px solid #1E293B', borderRadius: 8, overflow: 'hidden' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: 12 }}>
                    <thead>
                      <tr style={{ background: '#090D16', borderBottom: '1px solid #1E293B', color: '#94A3B8' }}>
                        <th style={{ padding: '10px 16px' }}>SYSTEM &amp; ACCOUNT</th>
                        <th style={{ padding: '10px 16px' }}>OWNER / DEPARTED EMPLOYEE</th>
                        <th style={{ padding: '10px 16px' }}>INACTIVITY</th>
                        <th style={{ padding: '10px 16px' }}>EVIDENCE &amp; AUDIT RATIONALE</th>
                        <th style={{ padding: '10px 16px' }}>SEVERITY</th>
                      </tr>
                    </thead>
                    <tbody>
                      {leavers.length === 0 ? (
                        <tr>
                          <td colSpan={5} style={{ padding: 32, textAlign: 'center', color: '#64748B' }}>
                            Zero active leavers detected. Clean offboarding hygiene!
                          </td>
                        </tr>
                      ) : (
                        leavers.map(lv => (
                          <tr key={lv.account_id} style={{ borderBottom: '1px solid #1E293B' }}>
                            <td style={{ padding: '12px 16px' }}>
                              <div style={{ fontWeight: 700, color: '#F8FAFC' }}>{lv.username}</div>
                              <div style={{ fontSize: 11, color: '#00E5FF' }}>System: {lv.system}</div>
                            </td>
                            <td style={{ padding: '12px 16px', color: '#E2E8F0', fontWeight: 600 }}>
                              {lv.owner || 'Unknown Former Employee'}
                            </td>
                            <td style={{ padding: '12px 16px', color: '#94A3B8' }}>
                              {lv.inactivity_days != null ? `${lv.inactivity_days} days ago` : 'Active'}
                            </td>
                            <td style={{ padding: '12px 16px', color: '#F87171', fontSize: 11 }}>
                              {lv.reasons?.map((r, ri) => <div key={ri}>• {r}</div>)}
                            </td>
                            <td style={{ padding: '12px 16px' }}>
                              <span style={{
                                fontSize: 10, padding: '3px 8px', borderRadius: 4,
                                background: 'rgba(239, 68, 68, 0.2)', color: '#EF4444', border: '1px solid #EF4444',
                                fontWeight: 800,
                              }}>
                                CRITICAL
                              </span>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* ══ SUB-TAB 3: ORPHAN ACCOUNTS ══ */}
            {activeSubTab === 'orphans' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div style={{ background: '#0D1526', border: '1px solid #1E293B', borderRadius: 8, overflow: 'hidden' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: 12 }}>
                    <thead>
                      <tr style={{ background: '#090D16', borderBottom: '1px solid #1E293B', color: '#94A3B8' }}>
                        <th style={{ padding: '10px 16px' }}>ACCOUNT ID &amp; USERNAME</th>
                        <th style={{ padding: '10px 16px' }}>SYSTEM</th>
                        <th style={{ padding: '10px 16px' }}>INACTIVITY</th>
                        <th style={{ padding: '10px 16px' }}>RISK FACTORS</th>
                        <th style={{ padding: '10px 16px' }}>RISK LEVEL</th>
                      </tr>
                    </thead>
                    <tbody>
                      {orphans.length === 0 ? (
                        <tr>
                          <td colSpan={5} style={{ padding: 32, textAlign: 'center', color: '#64748B' }}>
                            Zero orphan accounts detected.
                          </td>
                        </tr>
                      ) : (
                        orphans.map(op => (
                          <tr key={op.account_id} style={{ borderBottom: '1px solid #1E293B' }}>
                            <td style={{ padding: '12px 16px' }}>
                              <div style={{ fontWeight: 700, color: '#F8FAFC' }}>{op.username}</div>
                              <div style={{ fontSize: 11, color: '#64748B' }}>{op.account_id}</div>
                            </td>
                            <td style={{ padding: '12px 16px', color: '#00E5FF', fontWeight: 600 }}>
                              {op.system}
                            </td>
                            <td style={{ padding: '12px 16px', color: '#94A3B8' }}>
                              {op.inactivity_days != null ? `${op.inactivity_days} days` : 'Recent'}
                            </td>
                            <td style={{ padding: '12px 16px', color: '#FBBF24', fontSize: 11 }}>
                              {op.reasons?.map((r, ri) => <div key={ri}>• {r}</div>)}
                            </td>
                            <td style={{ padding: '12px 16px' }}>
                              <span style={{
                                fontSize: 10, padding: '3px 8px', borderRadius: 4,
                                background: op.risk_level === 'high' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(245, 158, 11, 0.15)',
                                color: op.risk_level === 'high' ? '#EF4444' : '#F59E0B',
                                fontWeight: 700,
                              }}>
                                {op.risk_level?.toUpperCase() || 'MEDIUM'}
                              </span>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* ══ SUB-TAB 4: REVIEW QUEUE (0.70 - 0.90 BAND) ══ */}
            {activeSubTab === 'review' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                <div style={{ fontSize: 13, color: '#94A3B8' }}>
                  The following match candidates fall into the <strong>0.70 – 0.90 confidence threshold</strong>. Confirm or reject each linkage to train the engine.
                </div>

                {reviewQueue.length === 0 ? (
                  <div style={{ textAlign: 'center', padding: 48, background: '#0D1526', border: '1px solid #1E293B', borderRadius: 8, color: '#64748B' }}>
                    <CheckCircle2 size={32} color="#10B981" style={{ margin: '0 auto 12px auto' }} />
                    <div style={{ fontWeight: 600, color: '#F8FAFC' }}>Review queue is clear!</div>
                    <div style={{ fontSize: 12, marginTop: 4 }}>All auto-merge threshold pairs (≥ 0.90) have been reconciled.</div>
                  </div>
                ) : (
                  reviewQueue.map(item => (
                    <div
                      key={item.item_id}
                      style={{
                        background: '#0D1526', border: '1px solid #1E293B', borderRadius: 8,
                        padding: 18, display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
                        {/* Account Box */}
                        <div style={{
                          background: '#090D16', border: '1px solid #1E293B', borderRadius: 6,
                          padding: '10px 14px', width: 220,
                        }}>
                          <div style={{ fontSize: 10, color: '#64748B', fontWeight: 700, textTransform: 'uppercase' }}>System Account</div>
                          <div style={{ fontSize: 13, fontWeight: 700, color: '#F8FAFC', marginTop: 2 }}>{item.account_id}</div>
                          <div style={{ fontSize: 11, color: '#00E5FF', marginTop: 2 }}>
                            {item.account_details?.system || 'System'}
                          </div>
                        </div>

                        {/* Middle Match Arrow */}
                        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
                          <span style={{
                            fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4,
                            background: 'rgba(59, 130, 246, 0.15)', color: '#60A5FA', border: '1px solid rgba(59, 130, 246, 0.3)',
                          }}>
                            {Math.round(item.confidence * 100)}% Confidence
                          </span>
                          <ArrowRight size={18} color="#64748B" />
                        </div>

                        {/* Suggested Identity Box */}
                        <div style={{
                          background: '#090D16', border: '1px solid #1E293B', borderRadius: 6,
                          padding: '10px 14px', width: 220,
                        }}>
                          <div style={{ fontSize: 10, color: '#64748B', fontWeight: 700, textTransform: 'uppercase' }}>Suggested HR Identity</div>
                          <div style={{ fontSize: 13, fontWeight: 700, color: '#F8FAFC', marginTop: 2 }}>
                            {item.identity_details?.full_name || item.suggested_identity_id}
                          </div>
                          <div style={{ fontSize: 11, color: '#94A3B8', marginTop: 2 }}>
                            {item.identity_details?.department || 'Corporate Identity'}
                          </div>
                        </div>

                        {/* Reasons */}
                        <div style={{ maxWidth: 320 }}>
                          <div style={{ fontSize: 11, fontWeight: 700, color: '#94A3B8', marginBottom: 4 }}>EVIDENCE SIGNALS</div>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                            {item.reasons?.map((r, ri) => (
                              <div key={ri} style={{ fontSize: 11, color: '#E2E8F0' }}>• {r}</div>
                            ))}
                          </div>
                        </div>
                      </div>

                      {/* Action Buttons */}
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <button
                          onClick={() => handleReviewDecision(item.item_id, 'reject')}
                          style={{
                            display: 'flex', alignItems: 'center', gap: 4,
                            background: '#1E293B', color: '#F87171', border: '1px solid #334155',
                            borderRadius: 6, padding: '7px 12px', fontSize: 12, fontWeight: 600, cursor: 'pointer',
                          }}
                        >
                          <X size={14} />
                          Reject
                        </button>
                        <button
                          onClick={() => handleReviewDecision(item.item_id, 'accept')}
                          style={{
                            display: 'flex', alignItems: 'center', gap: 4,
                            background: '#10B981', color: '#090D16', border: 'none',
                            borderRadius: 6, padding: '7px 14px', fontSize: 12, fontWeight: 700, cursor: 'pointer',
                          }}
                        >
                          <Check size={14} />
                          Accept &amp; Link
                        </button>
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}

            {/* ══ SUB-TAB 5: ALL CLASSIFICATIONS ══ */}
            {activeSubTab === 'all' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {/* Filter Pills */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, paddingBottom: 4 }}>
                  {['all', 'leaver_active', 'orphaned', 'shared', 'dormant', 'service', 'human'].map(f => (
                    <button
                      key={f}
                      onClick={() => setClassFilter(f)}
                      style={{
                        padding: '4px 10px', borderRadius: 4, fontSize: 11, fontWeight: 600,
                        cursor: 'pointer', textTransform: 'uppercase',
                        background: classFilter === f ? '#00E5FF' : '#1E293B',
                        color: classFilter === f ? '#090D16' : '#94A3B8',
                        border: 'none',
                      }}
                    >
                      {f.replace('_', ' ')}
                    </button>
                  ))}
                </div>

                <div style={{ background: '#0D1526', border: '1px solid #1E293B', borderRadius: 8, overflow: 'hidden' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: 12 }}>
                    <thead>
                      <tr style={{ background: '#090D16', borderBottom: '1px solid #1E293B', color: '#94A3B8' }}>
                        <th style={{ padding: '10px 16px' }}>USERNAME / ACCOUNT</th>
                        <th style={{ padding: '10px 16px' }}>SYSTEM</th>
                        <th style={{ padding: '10px 16px' }}>CLASSIFICATION</th>
                        <th style={{ padding: '10px 16px' }}>OWNER</th>
                        <th style={{ padding: '10px 16px' }}>INACTIVITY</th>
                        <th style={{ padding: '10px 16px' }}>RISK</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredClassifications.map(cl => (
                        <tr key={cl.account_id} style={{ borderBottom: '1px solid #1E293B' }}>
                          <td style={{ padding: '12px 16px' }}>
                            <div style={{ fontWeight: 700, color: '#F8FAFC' }}>{cl.username}</div>
                            <div style={{ fontSize: 11, color: '#64748B' }}>{cl.account_id}</div>
                          </td>
                          <td style={{ padding: '12px 16px', color: '#00E5FF', fontWeight: 600 }}>
                            {cl.system}
                          </td>
                          <td style={{ padding: '12px 16px' }}>
                            <span style={{
                              fontSize: 10, padding: '2px 8px', borderRadius: 4,
                              background: '#1E293B', color: '#E2E8F0', fontWeight: 700, textTransform: 'uppercase',
                            }}>
                              {cl.classification?.replace('_', ' ')}
                            </span>
                          </td>
                          <td style={{ padding: '12px 16px', color: '#94A3B8' }}>
                            {cl.owner || '—'}
                          </td>
                          <td style={{ padding: '12px 16px', color: '#94A3B8' }}>
                            {cl.inactivity_days != null ? `${cl.inactivity_days}d` : 'Recent'}
                          </td>
                          <td style={{ padding: '12px 16px' }}>
                            <span style={{
                              fontSize: 10, padding: '2px 6px', borderRadius: 4, fontWeight: 800,
                              background: cl.risk_level === 'critical' ? 'rgba(239,68,68,0.2)' : cl.risk_level === 'high' ? 'rgba(245,158,11,0.2)' : '#1E293B',
                              color: cl.risk_level === 'critical' ? '#EF4444' : cl.risk_level === 'high' ? '#F59E0B' : '#64748B',
                            }}>
                              {cl.risk_level?.toUpperCase()}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </>
        )}
      </div>

      {/* ── Manual Merge Modal ── */}
      {mergeModalOpen && (
        <div style={{
          position: 'fixed', inset: 0, background: 'rgba(9, 13, 22, 0.8)', backdropFilter: 'blur(4px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000,
        }}>
          <div style={{
            background: '#0D1526', border: '1px solid #1E293B', borderRadius: 8,
            width: 480, padding: 24, boxShadow: '0 20px 40px rgba(0,0,0,0.5)',
          }}>
            <div style={{ fontSize: 16, fontWeight: 700, color: '#F8FAFC', marginBottom: 4 }}>
              Merge Golden Identities
            </div>
            <div style={{ fontSize: 12, color: '#94A3B8', marginBottom: 18 }}>
              Transfer all linked accounts from the source identity into the target identity.
              Hard constraint: Cannot merge identities with conflicting non-null employee IDs.
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div>
                <label style={{ fontSize: 11, fontWeight: 600, color: '#CBD5E1', display: 'block', marginBottom: 4 }}>
                  TARGET IDENTITY ID (Retained)
                </label>
                <input
                  type="text"
                  placeholder="e.g. id_E1001 or gid_..."
                  value={targetMergeId}
                  onChange={e => setTargetMergeId(e.target.value)}
                  style={{
                    width: '100%', padding: '8px 12px', fontSize: 13,
                    background: '#090D16', border: '1px solid #1E293B', borderRadius: 6, color: '#F8FAFC',
                  }}
                />
              </div>

              <div>
                <label style={{ fontSize: 11, fontWeight: 600, color: '#CBD5E1', display: 'block', marginBottom: 4 }}>
                  SOURCE IDENTITY ID (Merged &amp; Removed)
                </label>
                <input
                  type="text"
                  placeholder="e.g. id_E1002 or gid_..."
                  value={sourceMergeId}
                  onChange={e => setSourceMergeId(e.target.value)}
                  style={{
                    width: '100%', padding: '8px 12px', fontSize: 13,
                    background: '#090D16', border: '1px solid #1E293B', borderRadius: 6, color: '#F8FAFC',
                  }}
                />
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 24 }}>
              <button
                onClick={() => setMergeModalOpen(false)}
                style={{
                  background: '#1E293B', color: '#E2E8F0', border: 'none',
                  borderRadius: 6, padding: '8px 14px', fontSize: 12, fontWeight: 600, cursor: 'pointer',
                }}
              >
                Cancel
              </button>
              <button
                onClick={handleMergeSubmit}
                style={{
                  background: 'linear-gradient(135deg, #00E5FF, #6366F1)', color: '#090D16', border: 'none',
                  borderRadius: 6, padding: '8px 18px', fontSize: 12, fontWeight: 700, cursor: 'pointer',
                }}
              >
                Confirm Merge
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
