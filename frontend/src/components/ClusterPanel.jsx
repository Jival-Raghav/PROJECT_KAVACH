import { Shield, Users } from 'lucide-react'
import ClusterScatterPlot from './ClusterScatterPlot'

/* ── Helpers ──────────────────────────────────────────── */

function riskBarColor(score) {
  if (score >= 60) return 'var(--c-critical)'
  if (score >= 40) return 'var(--c-review)'
  return 'var(--c-normal)'
}

function severityDot(level) {
  if (level === 'critical') return 'var(--c-critical)'
  if (level === 'high')     return 'var(--c-critical)'
  if (level === 'review')   return 'var(--c-review)'
  return 'var(--text-muted)'
}

/* ── Component ─────────────────────────────────────────── */

export default function ClusterPanel({ clusters, users, onSelectUser }) {
  if (!clusters || clusters.length === 0) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 120, color: 'var(--text-muted)', fontSize: 13 }}>
        Run the pipeline to see behavioral clusters.
      </div>
    )
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>

      {/* ── Header ── */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Shield size={15} style={{ color: 'var(--c-info)' }} />
          <span style={{ fontWeight: 600, fontSize: 14, color: 'var(--text-primary)' }}>Behavioral Clusters</span>
          <span className="badge-neutral">{clusters.length} groups</span>
        </div>
        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Aggregated from user activity patterns</span>
      </div>

      {/* ── Scatter plot ── */}
      <div className="card" style={{ padding: '12px 14px' }}>
        <div style={{ marginBottom: 8, fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 600, color: 'var(--text-muted)' }}>
          Risk Cluster Projection
        </div>
        <ClusterScatterPlot users={users} onSelectUser={onSelectUser} />
      </div>

      {/* ── Cluster cards grid ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: 10 }}>
        {clusters.map(cluster => (
          <article key={cluster.cluster_label} className="card slide-up" style={{ padding: 14 }}>

            {/* Title row */}
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8 }}>
              <div style={{ minWidth: 0 }}>
                <div style={{ fontWeight: 500, fontSize: 13, color: 'var(--text-primary)' }}>{cluster.description}</div>
                <div style={{ marginTop: 3, fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.09em', color: 'var(--text-muted)' }}>
                  Cluster {cluster.cluster_label}
                </div>
              </div>
              <span className="badge-neutral" style={{ flexShrink: 0 }}>
                <Users size={9} style={{ marginRight: 3 }} />
                {cluster.user_count}
              </span>
            </div>

            {/* Avg Risk bar */}
            <div style={{ marginTop: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--text-muted)', marginBottom: 5 }}>
                <span>Avg Risk</span>
                <span style={{ color: 'var(--text-secondary)' }}>{Number(cluster.avg_risk_score).toFixed(1)}</span>
              </div>
              <div className="risk-bar">
                <div
                  className="risk-bar-fill"
                  style={{ width: `${cluster.avg_risk_score}%`, background: riskBarColor(cluster.avg_risk_score) }}
                />
              </div>
            </div>

            {/* Top flags */}
            {(cluster.top_flags || []).length > 0 && (
              <div style={{ marginTop: 10, display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                {(cluster.top_flags || []).slice(0, 3).map(flag => (
                  <span key={flag} className="flag-tag neutral" style={{ textTransform: 'none', fontSize: 10 }}>
                    {flag.replace(/_/g, ' ')}
                  </span>
                ))}
              </div>
            )}

            {/* Severity breakdown */}
            <div style={{ marginTop: 10, paddingTop: 10, borderTop: '1px solid var(--border)', display: 'flex', gap: 12, fontSize: 11, color: 'var(--text-secondary)' }}>
              {[
                { label: 'critical', count: cluster.critical_count },
                { label: 'high',     count: cluster.high_count     },
                { label: 'review',   count: cluster.review_count   },
              ].map(({ label, count }) => (
                <span key={label} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  <span style={{ width: 6, height: 6, borderRadius: '50%', background: severityDot(label), flexShrink: 0 }} />
                  {count} {label}
                </span>
              ))}
            </div>
          </article>
        ))}
      </div>
    </div>
  )
}