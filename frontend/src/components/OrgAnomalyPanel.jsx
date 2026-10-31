import { Building2, TrendingUp, Users, AlertTriangle } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'

function barColor(score) {
  if (score > 35) return '#f43f5e'
  if (score > 28) return '#f97316'
  if (score > 22) return '#eab308'
  return '#22c55e'
}

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null
  const d = payload[0].payload
  return (
    <div className="glass rounded-xl border border-white/10 p-3 text-xs">
      <div className="font-semibold text-white">{d.department}</div>
      <div className="mt-1 text-slate-400">Avg Risk: <span className="text-white">{d.avg_score.toFixed(1)}</span></div>
      {d.count && <div className="text-slate-500">{d.count} anomalies</div>}
    </div>
  )
}

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
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="flex items-center gap-2 text-xl font-semibold text-white">
            <Building2 size={18} className="text-indigo-400" /> Org Anomalies
          </h2>
          <p className="mt-1 text-sm text-slate-400">
            {anomalies.length} users flagged as statistical outliers in their department
          </p>
        </div>
        <div className="text-right">
          <div className="text-2xl font-bold text-white">{anomalies.length}</div>
          <div className="text-xs text-slate-500 uppercase tracking-widest">Anomalies</div>
        </div>
      </div>

      {/* Bar chart */}
      {deptData.length > 0 && (
        <div className="glass rounded-2xl border border-white/10 p-4">
          <div className="mb-3 text-[11px] uppercase tracking-widest text-slate-500 flex items-center gap-2">
            <TrendingUp size={11} /> Avg Risk Score by Department
          </div>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={deptData} layout="vertical" barCategoryGap={6}>
              <XAxis type="number" domain={[0, 80]} tick={{ fill: '#475569', fontSize: 10 }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="department" tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} tickLine={false} width={90} />
              <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
              <Bar dataKey="avg_score" radius={[0, 4, 4, 0]}>
                {deptData.map((d, i) => <Cell key={i} fill={barColor(d.avg_score)} fillOpacity={0.85} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Anomaly cards */}
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {anomalies.map(user => (
          <article key={user.user_id} className="glass rounded-2xl border border-white/10 p-4 slide-up hover:border-white/20 transition">
            <div className="flex items-start justify-between gap-2">
              <div>
                <div className="font-medium text-white text-sm">{user.username}</div>
                <div className="mt-0.5 text-[11px] uppercase tracking-widest text-slate-500">{user.department}</div>
              </div>
              <span className="chip border border-rose-400/40 bg-rose-500/10 text-rose-300 shrink-0">
                {Number(user.risk_score).toFixed(0)}
              </span>
            </div>
            <div className="mt-3 rounded-xl border border-rose-500/20 bg-rose-500/8 p-3">
              <div className="flex gap-1.5 text-[10px] uppercase tracking-widest text-rose-400 mb-1">
                <AlertTriangle size={10} /> Org Reason
              </div>
              <div className="text-xs text-slate-300 leading-relaxed">
                {user.org_anomaly?.reason || 'Statistical outlier in department risk distribution.'}
              </div>
            </div>
            {user.org_anomaly?.dept_avg_score !== undefined && (
              <div className="mt-2 flex items-center justify-between text-[11px] text-slate-500">
                <span>Dept avg: {Number(user.org_anomaly.dept_avg_score).toFixed(1)}</span>
                <span className="text-rose-400">+{(user.risk_score - user.org_anomaly.dept_avg_score).toFixed(1)} above</span>
              </div>
            )}
          </article>
        ))}
      </div>

      {anomalies.length === 0 && (
        <div className="flex h-40 items-center justify-center text-sm text-slate-500">
          No org anomalies detected. Run the pipeline first.
        </div>
      )}
    </div>
  )
}
