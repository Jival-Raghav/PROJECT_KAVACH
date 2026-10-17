import { useState, useEffect } from 'react'
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  FileText,
  Download,
  CheckCircle,
  XCircle,
  Clock,
  Terminal,
  ExternalLink,
  ChevronRight,
  Filter,
  RefreshCw,
  Copy,
  AlertTriangle
} from 'lucide-react'

export default function Remediation() {
  const [proposals, setProposals] = useState([])
  const [auditLog, setAuditLog] = useState([])
  const [loading, setLoading] = useState(false)
  const [statusFilter, setStatusFilter] = useState('all')
  const [activeProposalModal, setActiveProposalModal] = useState(null)
  const [exportFormat, setExportFormat] = useState('ticket')
  const [exportPreview, setExportPreview] = useState('')
  const [copied, setCopied] = useState(false)
  const [viewTab, setViewTab] = useState('queue') // 'queue' | 'audit'

  const loadData = () => {
    setLoading(true)
    Promise.all([
      fetch('/api/remediation').then(res => res.json()),
      fetch('/api/remediation/audit/log').then(res => res.json()),
    ])
      .then(([propData, logData]) => {
        if (propData.status === 'success') setProposals(propData.proposals)
        if (logData.status === 'success') setAuditLog(logData.audit_log)
      })
      .catch(e => console.error('Failed to load remediation data:', e))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    loadData()
  }, [])

  const handleTransition = (proposalId, toStatus) => {
    fetch(`/api/remediation/${proposalId}/transition`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ to_status: toStatus, actor: 'SecOps_Analyst' }),
    })
      .then(res => res.json())
      .then(data => {
        if (data.status === 'success') {
          loadData()
          if (activeProposalModal?.proposal_id === proposalId) {
            setActiveProposalModal(data.proposal)
          }
        }
      })
      .catch(e => console.error('Transition error:', e))
  }

  const openExportModal = (prop) => {
    setActiveProposalModal(prop)
    fetchExportPreview(prop.proposal_id, exportFormat)
  }

  const fetchExportPreview = (propId, fmt) => {
    fetch(`/api/remediation/${propId}/export?format=${fmt}`)
      .then(res => res.text())
      .then(text => setExportPreview(text))
      .catch(e => console.error('Failed to fetch export:', e))
  }

  const copyToClipboard = () => {
    navigator.clipboard.writeText(exportPreview)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const filteredProposals = proposals.filter(p =>
    statusFilter === 'all' ? true : p.status === statusFilter
  )

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: 14 }}>
      {/* ── Top Header & Stats ── */}
      <div className="card" style={{ padding: '14px 18px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--text-muted)' }}>
            Least-Privilege Governance &amp; Remediation
          </div>
          <div style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)', marginTop: 2 }}>
            Remediation Queue &amp; Dry-Run Exporter
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
            Review, approve, and export platform-specific dry-run deprovisioning scripts. The system never executes mutations directly.
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ display: 'flex', background: 'var(--surface-mid)', borderRadius: 6, padding: 2, border: '1px solid var(--border)' }}>
            <button
              onClick={() => setViewTab('queue')}
              className={`nav-tab ${viewTab === 'queue' ? 'active' : ''}`}
              style={{ fontSize: 11, padding: '4px 12px' }}
            >
              Action Queue ({proposals.length})
            </button>
            <button
              onClick={() => setViewTab('audit')}
              className={`nav-tab ${viewTab === 'audit' ? 'active' : ''}`}
              style={{ fontSize: 11, padding: '4px 12px' }}
            >
              Immutable Audit Log ({auditLog.length})
            </button>
          </div>
          <button className="btn-ghost" onClick={loadData} title="Refresh">
            <RefreshCw size={13} className={loading ? 'spin-slow' : ''} />
          </button>
        </div>
      </div>

      {/* ── Content View ── */}
      {viewTab === 'queue' ? (
        <div style={{ display: 'flex', flexDirection: 'column', flex: 1, gap: 10, minHeight: 0 }}>
          {/* Filters Bar */}
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            {['all', 'proposed', 'approved', 'exported', 'rejected'].map(st => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                style={{
                  padding: '4px 12px', borderRadius: 4, fontSize: 11, textTransform: 'uppercase',
                  fontWeight: 600, letterSpacing: '0.05em', cursor: 'pointer',
                  background: statusFilter === st ? '#6366F1' : 'var(--surface-mid)',
                  color: statusFilter === st ? '#FFF' : 'var(--text-secondary)',
                  border: '1px solid var(--border)'
                }}
              >
                {st}
              </button>
            ))}
          </div>

          {/* Proposals Table */}
          <div className="card" style={{ flex: 1, overflow: 'auto', padding: 0 }}>
            <table className="risk-table">
              <thead>
                <tr>
                  <th>Proposal ID</th>
                  <th>Target Account / User</th>
                  <th>System</th>
                  <th>Action &amp; Entitlement</th>
                  <th>Severity</th>
                  <th>Impact</th>
                  <th>Status</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredProposals.length === 0 ? (
                  <tr>
                    <td colSpan="8" style={{ textAlign: 'center', padding: 24, color: 'var(--text-muted)' }}>
                      No remediation proposals match the current filter.
                    </td>
                  </tr>
                ) : (
                  filteredProposals.map(prop => (
                    <tr key={prop.proposal_id}>
                      <td className="mono" style={{ fontWeight: 600, color: '#00E5FF' }}>
                        {prop.proposal_id}
                      </td>
                      <td>
                        <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{prop.target_account}</div>
                        <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>{prop.target_identity}</div>
                      </td>
                      <td>
                        <span className="mono" style={{ fontSize: 11 }}>{prop.target_system}</span>
                      </td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                          <span style={{ fontSize: 11, color: '#F59E0B' }}>REVOKE</span>
                          <span className="mono" style={{ fontWeight: 600 }}>{prop.entitlement}</span>
                        </div>
                        <div style={{ fontSize: 10, color: 'var(--text-secondary)' }}>{prop.reason}</div>
                      </td>
                      <td>
                        <span className={`flag-tag ${prop.risk_severity === 'critical' ? 'critical' : 'high'}`}>
                          {prop.risk_severity.toUpperCase()}
                        </span>
                      </td>
                      <td>
                        <span className={`flag-tag ${prop.impact_classification === 'safe' ? 'safe' : prop.impact_classification === 'review' ? 'review' : 'critical'}`}>
                          {prop.impact_classification.toUpperCase()}
                        </span>
                      </td>
                      <td>
                        <span style={{
                          fontSize: 10, fontWeight: 700, padding: '3px 8px', borderRadius: 4,
                          textTransform: 'uppercase', letterSpacing: '0.06em',
                          background: prop.status === 'approved' ? 'rgba(16, 185, 129, 0.15)' :
                                      prop.status === 'exported' ? 'rgba(168, 85, 247, 0.15)' :
                                      prop.status === 'rejected' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(99, 102, 241, 0.15)',
                          color: prop.status === 'approved' ? '#10B981' :
                                 prop.status === 'exported' ? '#A855F7' :
                                 prop.status === 'rejected' ? '#EF4444' : '#6366F1',
                          border: '1px solid var(--border)'
                        }}>
                          {prop.status}
                        </span>
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <div style={{ display: 'inline-flex', gap: 6 }}>
                          {prop.status === 'proposed' && (
                            <>
                              <button
                                className="btn-primary"
                                style={{ padding: '3px 8px', fontSize: 10, background: '#10B981' }}
                                onClick={() => handleTransition(prop.proposal_id, 'approved')}
                              >
                                Approve
                              </button>
                              <button
                                className="btn-ghost"
                                style={{ padding: '3px 8px', fontSize: 10, color: '#EF4444' }}
                                onClick={() => handleTransition(prop.proposal_id, 'rejected')}
                              >
                                Reject
                              </button>
                            </>
                          )}
                          <button
                            className="btn-secondary"
                            style={{ padding: '3px 8px', fontSize: 10 }}
                            onClick={() => openExportModal(prop)}
                          >
                            <Terminal size={11} /> Export
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        /* Immutable Audit Log Table */
        <div className="card" style={{ flex: 1, overflow: 'auto', padding: 0 }}>
          <table className="risk-table">
            <thead>
              <tr>
                <th>Timestamp (UTC)</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Proposal ID</th>
                <th>Target</th>
                <th>Transition</th>
              </tr>
            </thead>
            <tbody>
              {auditLog.map((log, idx) => (
                <tr key={idx}>
                  <td className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                    {log.timestamp}
                  </td>
                  <td style={{ fontWeight: 600 }}>{log.actor}</td>
                  <td>
                    <span className="mono" style={{ fontSize: 11, color: '#00E5FF' }}>{log.action}</span>
                  </td>
                  <td className="mono">{log.proposal_id}</td>
                  <td>{log.target_account}</td>
                  <td>
                    <span className="mono" style={{ fontSize: 10 }}>
                      {log.from_status || 'INIT'} &rarr; {log.to_status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* ── Dry-Run Script Export Modal ── */}
      {activeProposalModal && (
        <div className="modal-backdrop" style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(4px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000
        }}>
          <div className="card slide-up" style={{ width: 680, maxHeight: '85vh', display: 'flex', flexDirection: 'column', padding: 20 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <div>
                <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--text-muted)' }}>
                  Dry-Run Code Generator
                </div>
                <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)' }}>
                  Remediation Script: {activeProposalModal.proposal_id}
                </div>
              </div>
              <button className="btn-icon" onClick={() => setActiveProposalModal(null)}>
                &times;
              </button>
            </div>

            {/* Platform Selector */}
            <div style={{ display: 'flex', gap: 6, marginBottom: 12 }}>
              {[
                { id: 'aws', label: 'AWS IAM CLI' },
                { id: 'entra', label: 'Entra PowerShell' },
                { id: 'okta', label: 'Okta API' },
                { id: 'ad', label: 'AD PowerShell' },
                { id: 'ticket', label: 'Jira Ticket' },
                { id: 'csv', label: 'CSV' },
              ].map(f => (
                <button
                  key={f.id}
                  onClick={() => {
                    setExportFormat(f.id)
                    fetchExportPreview(activeProposalModal.proposal_id, f.id)
                  }}
                  style={{
                    padding: '4px 10px', borderRadius: 4, fontSize: 11, cursor: 'pointer',
                    background: exportFormat === f.id ? '#6366F1' : 'var(--surface-mid)',
                    color: exportFormat === f.id ? '#FFF' : 'var(--text-secondary)',
                    border: '1px solid var(--border)'
                  }}
                >
                  {f.label}
                </button>
              ))}
            </div>

            {/* Script Display */}
            <div style={{ flex: 1, position: 'relative', minHeight: 280, overflow: 'hidden', borderRadius: 6, border: '1px solid var(--border)' }}>
              <pre className="mono" style={{
                margin: 0, padding: 14, height: '100%', overflow: 'auto',
                background: '#090D16', color: '#38BDF8', fontSize: 11, lineHeight: 1.5
              }}>
                {exportPreview}
              </pre>
              <button
                className="btn-secondary"
                onClick={copyToClipboard}
                style={{ position: 'absolute', top: 8, right: 8, padding: '4px 8px', fontSize: 10 }}
              >
                {copied ? <CheckCircle size={11} color="#10B981" /> : <Copy size={11} />}
                {copied ? 'Copied!' : 'Copy Script'}
              </button>
            </div>

            {/* Bottom Actions */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 14 }}>
              <div style={{ fontSize: 10, color: '#F59E0B', display: 'flex', alignItems: 'center', gap: 4 }}>
                <AlertTriangle size={12} /> Scripts are non-executable simulations. Review prior to operational execution.
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <a
                  href={`/api/remediation/${activeProposalModal.proposal_id}/export?format=${exportFormat}`}
                  download
                  className="btn-primary"
                  style={{ padding: '6px 14px', fontSize: 11, gap: 6, textDecoration: 'none' }}
                >
                  <Download size={12} /> Download Artifact
                </a>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
