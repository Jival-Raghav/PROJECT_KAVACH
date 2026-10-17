import { Shield, ShieldAlert, Cpu, Database, KeyRound, Building2, Calendar, FileWarning, X, Scale } from 'lucide-react'

/* ── Helpers ──────────────────────────────────────────── */

function privilegeColor(level) {
  if (level === 'admin')       return { bg: 'var(--c-critical-bg)', color: 'var(--c-critical)' }
  if (level === 'power-user')  return { bg: 'var(--c-review-bg)',   color: 'var(--c-review)'   }
  return                              { bg: 'var(--surface-high)',   color: 'var(--text-secondary)' }
}

/* ── Component ─────────────────────────────────────────── */

export default function UserCard({ user, onClose, onInvestigate }) {
  if (!user) return null

  const isHighRisk = user.risk_score >= 60
  const initial    = user.username?.[0]?.toUpperCase() || '?'
  const priv       = privilegeColor(user.privilege_level)

  return (
    <section className="card slide-up" style={{ padding: 14, position: 'relative', overflow: 'hidden', flexShrink: 0 }}>

      {/* Header row */}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, marginBottom: 12 }}>
        {/* Avatar */}
        <div style={{
          width: 42, height: 42, borderRadius: '50%', flexShrink: 0,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: isHighRisk ? 'var(--c-critical-bg)' : 'var(--surface-high)',
          border: isHighRisk ? '1px solid var(--c-critical-bd)' : '1px solid var(--border)',
          color: isHighRisk ? 'var(--c-critical)' : 'var(--text-primary)',
          fontSize: 16, fontWeight: 700,
        }}>
          {initial}
        </div>

        {/* Name + ID */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--text-muted)', marginBottom: 2 }}>
            Target Profile
          </div>
          <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {user.username}
          </div>
          <div className="mono" style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 3 }}>{user.user_id}</div>
        </div>

        {/* Close button */}
        <button
          onClick={onClose}
          className="btn-icon"
          style={{ flexShrink: 0 }}
          title="Dismiss"
        >
          <X size={14} />
        </button>
      </div>

      {/* Field grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
        <Field icon={Building2}  label="Department" value={user.department} />
        <Field icon={KeyRound}   label="Privilege"  value={user.privilege_level} highlight={user.privilege_level === 'admin'} />
        <Field icon={Database}   label="Peer Group" value={user.peer_group || user.cluster_description || 'General'} highlight={user.is_peer_outlier} />
        <Field icon={FileWarning}label="Peer Z-Score" value={user.peer_zscore ? `${user.peer_zscore.toFixed(2)}σ` : '0.00σ'} highlight={user.is_peer_outlier} />
        {user.last_login   && <Field icon={Calendar} label="Last Login"    value={new Date(user.last_login).toLocaleDateString()} />}
        {user.days_inactive !== undefined && <Field icon={Calendar} label="Days Inactive" value={user.days_inactive} highlight={user.days_inactive > 30} />}
      </div>

      {/* Score Fusion Breakdown */}
      {user.ml_score !== undefined && (
        <div style={{ marginTop: 10, padding: '8px 10px', background: 'var(--surface-mid)', borderRadius: 4, border: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.09em', color: 'var(--text-muted)', marginBottom: 4 }}>
            <span>Score Fusion (60% ML / 40% Heuristics)</span>
            <span style={{ fontWeight: 700, color: 'var(--text-primary)' }}>Risk {user.risk_score}</span>
          </div>
          <div style={{ display: 'flex', gap: 8, fontSize: 11 }}>
            <div>ML Isolation: <strong className="mono">{user.ml_score}</strong></div>
            <div style={{ color: 'var(--border)' }}>|</div>
            <div>Heuristics/SoD: <strong className="mono">{user.heuristic_score}</strong></div>
          </div>
        </div>
      )}

      {/* Security Findings & SoD Violations */}
      {user.findings?.length > 0 && (
        <div style={{ marginTop: 10, paddingTop: 10, borderTop: '1px solid var(--border)' }}>
          <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.09em', color: 'var(--text-muted)', marginBottom: 6 }}>
            Security Findings & SoD Violations ({user.findings.length})
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {user.findings.map((f, i) => (
              <div key={i} style={{
                fontSize: 11, padding: '5px 8px', borderRadius: 4,
                background: f.severity === 'critical' ? 'var(--c-critical-bg)' : 'var(--surface-high)',
                border: `1px solid ${f.severity === 'critical' ? 'var(--c-critical-bd)' : 'var(--border)'}`,
                color: f.severity === 'critical' ? 'var(--c-critical)' : 'var(--text-primary)',
              }}>
                <div style={{ fontWeight: 600 }}>{f.name}</div>
                <div style={{ fontSize: 10, color: 'var(--text-secondary)', marginTop: 2 }}>{f.description}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Systems access */}
      {user.systems_access?.length > 0 && (
        <div style={{ marginTop: 10, paddingTop: 10, borderTop: '1px solid var(--border)' }}>
          <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.09em', color: 'var(--text-muted)', marginBottom: 6 }}>
            Provisioned Systems
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
            {user.systems_access.map(sys => (
              <span key={sys} className="flag-tag neutral">{sys}</span>
            ))}
          </div>
        </div>
      )}

      {/* Investigate Case CTA */}
      {onInvestigate && (
        <button
          className="btn-primary"
          style={{ width: '100%', marginTop: 12, justifyContent: 'center', gap: 6 }}
          onClick={() => onInvestigate(user)}
        >
          <Scale size={13} />
          Investigate Case (3-Pass Arena)
        </button>
      )}
    </section>
  )
}

/* ── Field helper ──────────────────────────────────────── */
function Field({ icon: Icon, label, value, highlight }) {
  return (
    <div style={{
      borderRadius: 4, padding: '8px 10px',
      background: highlight ? 'var(--c-critical-bg)' : 'var(--surface-mid)',
      border: `1px solid ${highlight ? 'var(--c-critical-bd)' : 'var(--border)'}`,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.09em', color: highlight ? 'var(--c-critical)' : 'var(--text-muted)', marginBottom: 4 }}>
        <Icon size={9} /> {label}
      </div>
      <div style={{ fontSize: 12, fontWeight: 500, color: highlight ? 'var(--c-critical)' : 'var(--text-primary)' }}>
        {value}
      </div>
    </div>
  )
}
