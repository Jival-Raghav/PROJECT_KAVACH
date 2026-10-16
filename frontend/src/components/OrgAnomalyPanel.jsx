import { Building2, TrendingUp, AlertTriangle } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'

/* ── Helpers ──────────────────────────────────────────── */

function barColor(score) {
  if (score > 35) return 'var(--c-critical)'
  if (score > 28) return 'var(--c-review)'
  if (score > 22) return 'var(--c-review)'
  return 'var(--c-normal)'
}

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null
  const d = payload[0].payload
  return (
    <div style={{
      background: 'var(--surface)', border: '1px solid var(--border)',
      borderRadius: 6, padding: '8px 12px', fontSize: 12,
    }}>
      <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{d.department}</div>
      <div style={{ marginTop: 4, color: 'var(--text-secondary)' }}>
        Avg Risk: <span style={{ color: 'var(--text-primary)' }}>{d.avg_score.toFixed(1)}</span>
      </div>
      {d.count && <div style={{ color: 'var(--text-muted)' }}>{d.count} anomalies</div>}
    </div>
  )
}

/* ── Component ─────────────────────────────────────────── */

export default function OrgAnomalyPanel({ anomalies, stats }) {
  // Build department stats from anomalies list
  const deptMap = {}
  anomalies.forEach(u => {
    const d = u.department || 'Unknown'
    if (!deptMap[d]) deptMap[d] = { department: d, scores: [], count: 0 }
    deptMap[d].scores.push(u.risk_score || 0)
    if (u.org_anomaly?.is_anomaly) deptMap[d].count++
  })

  const deptData = Object.values(deptMap)
    .map(d => ({ ...d, avg_score: d.scores.reduce((a, b) => a + b, 0) / d.scores.length }))
    .sort((a, b) => b.avg_score - a.avg_score)
    .slice(0, 10)

  // Top dept risks from /stats
  const topDepts = stats?.top_risky_departments || []

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>

      {/* ── Header ── */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Building2 size={15} style={{ color: 'var(--c-info)' }} />
          <span style={{ fontWeight: 600, fontSize: 14, color: 'var(--text-primary)' }}>Org Anomalies</span>
          <span className="badge-neutral">{anomalies.length} flagged</span>
        </div>
        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
          Statistical outliers by department
        </span>
      </div>

      {/* ── Bar chart ── */}
      {deptData.length > 0 && (
        <div className="card" style={{ padding: '12px 14px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 10, fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 600 }}>
            <TrendingUp size={11} /> Avg Risk Score by Department
          </div>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={deptData} layout="vertical" barCategoryGap={6}>
              <XAxis type="number" domain={[0, 80]} tick={{ fill: 'var(--text-muted)', fontSize: 10 }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="department" tick={{ fill: 'var(--text-secondary)', fontSize: 11 }} axisLine={false} tickLine={false} width={90} />
              <Tooltip content={<CustomTooltip />} cursor={{ fill: 'var(--surface-mid)' }} />
              <Bar dataKey="avg_score" radius={[0, 3, 3, 0]}>
                {deptData.map((d, i) => <Cell key={i} fill={barColor(d.avg_score)} fillOpacity={0.85} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* ── Anomaly cards grid ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))', gap: 10 }}>
        {anomalies.map(user => (
          <article key={user.user_id} className="card slide-up" style={{ padding: 14 }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8 }}>
              <div>
                <div style={{ fontWeight: 500, fontSize: 13, color: 'var(--text-primary)' }}>{user.username}</div>
                <div style={{ marginTop: 2, fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)' }}>
                  {user.department}
                </div>
              </div>
              <span className="badge-critical" style={{ flexShrink: 0 }}>
                {Number(user.risk_score).toFixed(0)}
              </span>
            </div>

            <div style={{
              marginTop: 10, borderRadius: 4, border: '1px solid var(--c-critical-bd)',
              background: 'var(--c-critical-bg)', padding: '8px 10px',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--c-critical)', marginBottom: 4 }}>
                <AlertTriangle size={10} /> Org Reason
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                {user.org_anomaly?.reason || 'Statistical outlier in department risk distribution.'}
              </div>
            </div>

            {user.org_anomaly?.dept_baseline?.avg_risk_score !== undefined && (() => {
              const deptAvg = user.org_anomaly?.dept_baseline?.avg_risk_score
              return (
                <div style={{ marginTop: 8, display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--text-muted)' }}>
                  <span>Dept avg: {Number(deptAvg).toFixed(1)}</span>
                  <span style={{ color: 'var(--c-critical)' }}>+{(user.risk_score - deptAvg).toFixed(1)} above</span>
                </div>
              )
            })()}
          </article>
        ))}
      </div>

      {anomalies.length === 0 && (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 120, color: 'var(--text-muted)', fontSize: 13 }}>
          No org anomalies detected. Run the pipeline first.
        </div>
      )}
    </div>
  )
}
