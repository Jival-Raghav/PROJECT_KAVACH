import { Shield, ShieldAlert, Cpu, Database, KeyRound, Building2, Calendar, FileWarning, X } from 'lucide-react'

/* ── Helpers ──────────────────────────────────────────── */

function privilegeColor(level) {
  if (level === 'admin')       return { bg: 'var(--c-critical-bg)', color: 'var(--c-critical)' }
  if (level === 'power-user')  return { bg: 'var(--c-review-bg)',   color: 'var(--c-review)'   }
  return                              { bg: 'var(--surface-high)',   color: 'var(--text-secondary)' }
}

/* ── Component ─────────────────────────────────────────── */

export default function UserCard({ user, onClose }) {
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
        <Field icon={Database}   label="Cluster"    value={user.cluster_description || 'Unknown'} />
        <Field icon={FileWarning}label="Events"     value={`${user.event_count || 0} analysed`} />
        {user.last_login   && <Field icon={Calendar} label="Last Login"    value={new Date(user.last_login).toLocaleDateString()} />}
        {user.days_inactive !== undefined && <Field icon={Calendar} label="Days Inactive" value={user.days_inactive} highlight={user.days_inactive > 30} />}
      </div>

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
