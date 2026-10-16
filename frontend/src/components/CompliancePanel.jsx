import { useState } from 'react'
import { ShieldCheck, ShieldAlert, FileWarning } from 'lucide-react'

/* ── Constants ────────────────────────────────────────── */

const FRAMEWORK_META = {
  'NIST AC-2':   { icon: ShieldCheck,  badgeCls: 'badge-info'     },
  'NIST AC-6':   { icon: ShieldAlert,  badgeCls: 'badge-critical' },
  'GDPR Art. 32':{ icon: FileWarning,  badgeCls: 'badge-review'   },
}

const SEV_CLS = {
  HIGH:   'badge-critical',
  MEDIUM: 'badge-review',
  LOW:    'badge-neutral',
}

const ALL_FRAMEWORKS = ['NIST AC-2', 'NIST AC-6', 'GDPR Art. 32']

/* ── Component ─────────────────────────────────────────── */

export default function CompliancePanel({ users }) {
  const [activeFilters, setActiveFilters] = useState([]) // visual-only filter state

  const withGaps  = users.filter(u => (u.compliance_gaps || []).length > 0)
  const totalGaps = users.reduce((s, u) => s + (u.compliance_gaps || []).length, 0)

  // Framework breakdown counts
  const fwCount = {}
  users.forEach(u => (u.compliance_gaps || []).forEach(g => {
    const fw = `${g.framework || 'Other'} ${g.control_id || ''}`.trim()
    fwCount[fw] = (fwCount[fw] || 0) + 1
  }))

  const toggleFilter = fw => {
    setActiveFilters(prev =>
      prev.includes(fw) ? prev.filter(f => f !== fw) : [...prev, fw]
    )
  }

  // Apply visual filter: if no filters active, show all; else show only matching
  const filteredUsers = activeFilters.length === 0
    ? withGaps
    : withGaps.filter(u =>
        (u.compliance_gaps || []).some(g => {
          const fw = `${g.framework || 'Other'} ${g.control_id || ''}`.trim()
          return activeFilters.some(f => fw.startsWith(f))
        })
      )

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>

      {/* ── Header ── */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <ShieldCheck size={15} style={{ color: 'var(--c-info)' }} />
          <span style={{ fontWeight: 600, fontSize: 14, color: 'var(--text-primary)' }}>Compliance Gaps</span>
          <span className="badge-neutral">{totalGaps} violations</span>
        </div>
        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{withGaps.length} users affected</span>
      </div>

      {/* ── Filter chips ── */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
        {ALL_FRAMEWORKS.map(fw => {
          const meta = FRAMEWORK_META[fw] || { icon: ShieldCheck, badgeCls: 'badge-neutral' }
          const Icon = meta.icon
          const count = fwCount[fw] || 0
          const isActive = activeFilters.includes(fw)
          return (
            <button
              key={fw}
              className={`filter-chip${isActive ? ' active' : ''}`}
              onClick={() => toggleFilter(fw)}
            >
              <Icon size={10} />
              {fw}
              {count > 0 && <span style={{ marginLeft: 2, opacity: 0.7 }}>· {count}</span>}
            </button>
          )
        })}
        {activeFilters.length > 0 && (
          <button
            className="filter-chip"
            onClick={() => setActiveFilters([])}
            style={{ color: 'var(--text-muted)', fontSize: 10 }}
          >
            Clear
          </button>
        )}
      </div>

      {/* ── User cards grid — 2 columns ── */}
      {filteredUsers.length === 0 ? (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 120, color: 'var(--text-muted)', fontSize: 13 }}>
          {withGaps.length === 0 ? 'No compliance gaps detected. Run the pipeline first.' : 'No gaps match selected filters.'}
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 10 }}>
          {filteredUsers.map(user => {
            const gaps = (user.compliance_gaps || []).filter(g => {
              if (activeFilters.length === 0) return true
              const fw = `${g.framework || 'Other'} ${g.control_id || ''}`.trim()
              return activeFilters.some(f => fw.startsWith(f))
            })

            return (
              <article key={user.user_id} className="card slide-up" style={{ padding: 14 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, marginBottom: 10 }}>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontWeight: 500, fontSize: 13, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {user.username}
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                      {user.department} · {user.privilege_level} · <span className="mono">{user.user_id}</span>
                    </div>
                  </div>
                  <span className="badge-critical" style={{ flexShrink: 0 }}>
                    {gaps.length} gap{gaps.length !== 1 ? 's' : ''}
                  </span>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {gaps.map((gap, i) => {
                    const displayKey = `${gap.framework || 'Other'} ${gap.control_id || ''}`.trim()
                    const meta = FRAMEWORK_META[displayKey] || { icon: ShieldAlert, badgeCls: 'badge-neutral' }
                    const Icon = meta.icon
                    const sevCls = SEV_CLS[gap.severity] || SEV_CLS.LOW
                    return (
                      <div key={i} style={{
                        borderRadius: 4, border: '1px solid var(--border)',
                        background: 'var(--surface-mid)', padding: '8px 10px',
                      }}>
                        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 6, marginBottom: 6 }}>
                          <span className={meta.badgeCls} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                            <Icon size={9} /> {displayKey}
                          </span>
                          <span className={sevCls}>{gap.severity}</span>
                          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{gap.control_name}</span>
                        </div>
                        <p style={{ fontSize: 12, lineHeight: 1.55, color: 'var(--text-secondary)', margin: 0 }}>{gap.gap}</p>
                      </div>
                    )
                  })}
                </div>
              </article>
            )
          })}
        </div>
      )}
    </div>
  )
}
