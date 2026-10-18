import { useState, useEffect } from 'react'
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  FileText,
  Download,
  AlertTriangle,
  CheckCircle,
  XCircle,
  HelpCircle,
  TrendingUp,
  RefreshCw,
  ExternalLink,
  ChevronRight,
  Layers,
  Award
} from 'lucide-react'

export default function Compliance() {
  const [scoreData, setScoreData] = useState(null)
  const [complianceData, setComplianceData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [activeFw, setActiveFw] = useState('all')

  const loadComplianceData = () => {
    setLoading(true)
    Promise.all([
      fetch('/api/posture/score').then(res => res.json()),
      fetch('/api/posture/controls').then(res => res.json()),
    ])
      .then(([scoreRes, compRes]) => {
        if (scoreRes.status === 'success') setScoreData(scoreRes.data)
        if (compRes.status === 'success') setComplianceData(compRes)
      })
      .catch(e => console.error('Failed to load compliance data:', e))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    loadComplianceData()
  }, [])

  const filteredControls = complianceData?.controls?.filter(c =>
    activeFw === 'all' ? true : c.framework === activeFw
  ) || []

  const frameworks = ['all', 'NIST SP 800-53', 'ISO/IEC 27001:2022', 'India DPDP Act 2023']

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: 14, overflowY: 'auto' }}>
      {/* ── Top Header Bar ── */}
      <div className="card" style={{ padding: '14px 18px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--text-muted)' }}>
            Enterprise Posture &amp; Continuous Compliance
          </div>
          <div style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)', marginTop: 2 }}>
            Identity Hygiene &amp; Regulatory Control Center
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
            Continuous evaluation across NIST SP 800-53, ISO 27001:2022, and India DPDP Act 2023.
          </div>
        </div>

        {/* Download Audit Pack Dropdown */}
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <a
            href="/api/posture/export?format=pdf"
            download
            className="btn-primary"
            style={{ textDecoration: 'none', gap: 6, fontSize: 11 }}
          >
            <Download size={12} /> Export PDF Report
          </a>
          <a
            href="/api/posture/export?format=json"
            download
            className="btn-secondary"
            style={{ textDecoration: 'none', gap: 6, fontSize: 11 }}
          >
            <FileText size={12} /> JSON Pack
          </a>
          <a
            href="/api/posture/export?format=csv"
            download
            className="btn-secondary"
            style={{ textDecoration: 'none', gap: 6, fontSize: 11 }}
          >
            <Download size={12} /> CSV
          </a>
          <button className="btn-ghost" onClick={loadComplianceData} title="Refresh">
            <RefreshCw size={13} className={loading ? 'spin-slow' : ''} />
          </button>
        </div>
      </div>

      {/* ── Executive Scorecard Row ── */}
      {scoreData && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1.2fr', gap: 14 }}>
          {/* 1. Identity Hygiene Score */}
          <div className="card" style={{ padding: 16, display: 'flex', alignItems: 'center', gap: 16 }}>
            <div style={{
              width: 80, height: 80, borderRadius: '50%', flexShrink: 0,
              background: 'var(--accent-subtle)',
              border: '2px solid var(--accent)', display: 'flex', flexDirection: 'column',
              alignItems: 'center', justifyContent: 'center'
            }}>
              <span style={{ fontSize: 22, fontWeight: 900, color: 'var(--accent-ink)' }}>
                {scoreData.identity_hygiene_score}
              </span>
              <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>/ 100</span>
            </div>

            <div>
              <div style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.08em' }}>
                Overall Hygiene Score
              </div>
              <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)', marginTop: 2 }}>
                Grade {scoreData.grade} Posture
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 4 }}>
                Calculated from 9 dynamically weighted identity hygiene telemetry domains.
              </div>
            </div>
          </div>

          {/* 2. Insurer Exposure Indicator */}
          <div className="card" style={{ padding: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <div style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.08em' }}>
                  Cyber Insurance Exposure
                </div>
                <div style={{ fontSize: 16, fontWeight: 700, color: '#F59E0B', marginTop: 2 }}>
                  {scoreData.insurer_exposure.tier} RISK
                </div>
              </div>
              <span className="mono" style={{
                fontSize: 12, fontWeight: 800, padding: '2px 8px', borderRadius: 4,
                background: 'rgba(245, 158, 11, 0.15)', color: '#F59E0B', border: '1px solid rgba(245, 158, 11, 0.3)'
              }}>
                Index {scoreData.insurer_exposure.exposure_index}x
              </span>
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 6 }}>
              {scoreData.insurer_exposure.rationale}
            </div>
            <div style={{ fontSize: 9, color: 'var(--text-muted)', fontStyle: 'italic', marginTop: 6 }}>
              *Indicative risk exposure indicator for cyber underwriting. Not an actuarial calculation.
            </div>
          </div>

          {/* 3. Top Negative Posture Drivers */}
          <div className="card" style={{ padding: 16 }}>
            <div style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.08em', marginBottom: 8 }}>
              Top Remediation Drivers (Largest Deductions)
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {scoreData.top_drivers.map((d, i) => (
                <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 11 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ color: '#EF4444', fontWeight: 700 }}>-{d.deduction_points}pts</span>
                    <span style={{ color: 'var(--text-primary)', textTransform: 'capitalize' }}>
                      {d.subscore.replace(/_/g, ' ')}
                    </span>
                  </div>
                  <span className="mono" style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                    Weight {d.weight_pct}%
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── Framework Filter & Controls Table ── */}
      <div className="card" style={{ flex: 1, display: 'flex', flexDirection: 'column', padding: 0, minHeight: 400 }}>
        {/* Framework Tabs */}
        <div style={{ display: 'flex', gap: 8, padding: '12px 16px', borderBottom: '1px solid var(--border)', background: 'var(--surface-mid)' }}>
          {frameworks.map(fw => (
            <button
              key={fw}
              onClick={() => setActiveFw(fw)}
              style={{
                padding: '4px 12px', borderRadius: 4, fontSize: 11, cursor: 'pointer',
                fontWeight: 600, letterSpacing: '0.04em',
                background: activeFw === fw ? '#6366F1' : 'transparent',
                color: activeFw === fw ? '#FFF' : 'var(--text-secondary)',
                border: activeFw === fw ? '1px solid #6366F1' : '1px solid var(--border)'
              }}
            >
              {fw === 'all' ? 'All Frameworks' : fw}
            </button>
          ))}
        </div>

        {/* Controls Table */}
        <div style={{ flex: 1, overflow: 'auto' }}>
          <table className="risk-table">
            <thead>
              <tr>
                <th style={{ width: 110 }}>Control ID</th>
                <th style={{ width: 140 }}>Framework</th>
                <th style={{ width: 220 }}>Title &amp; Objective</th>
                <th style={{ width: 100 }}>Status</th>
                <th>Automated Evidence Findings</th>
              </tr>
            </thead>
            <tbody>
              {filteredControls.map(c => {
                const st = c.status.toLowerCase()
                return (
                  <tr key={c.id}>
                    <td className="mono" style={{ fontWeight: 700, color: 'var(--accent-ink)' }}>
                      {c.id}
                    </td>
                    <td style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                      {c.framework}
                    </td>
                    <td>
                      <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{c.title}</div>
                      <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>{c.description}</div>
                    </td>
                    <td>
                      <span className={`flag-tag ${st === 'pass' ? 'safe' : st === 'partial' ? 'review' : st === 'fail' ? 'critical' : 'neutral'}`}>
                        {c.status.toUpperCase()}
                      </span>
                    </td>
                    <td style={{ fontSize: 11, color: 'var(--text-primary)' }}>
                      {c.evidence}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>

        {/* Audit Disclaimer Footer */}
        <div style={{ padding: '8px 16px', background: 'var(--surface-mid)', borderTop: '1px solid var(--border)', fontSize: 10, color: 'var(--text-muted)' }}>
          *Automated compliance evidence generated by Kavach v2. Regulatory compliance determinations must be validated by licensed assessors.
        </div>
      </div>
    </div>
  )
}
