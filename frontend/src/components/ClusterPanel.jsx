import { Shield, Users } from 'lucide-react'
import ClusterScatterPlot from './ClusterScatterPlot'

function riskGradient(score) {
  if (score >= 70) return 'from-rose-500 to-red-600'
  if (score >= 50) return 'from-orange-400 to-amber-500'
  if (score >= 30) return 'from-yellow-400 to-amber-400'
  return 'from-emerald-400 to-teal-500'
}

function dotClass(level) {
  if (level === 'critical') return 'bg-rose-400'
  if (level === 'high') return 'bg-orange-400'
  if (level === 'review') return 'bg-yellow-400'
  return 'bg-slate-400'
}

export default function ClusterPanel({ clusters, users, onSelectUser }) {
  if (!clusters || clusters.length === 0) {
    return (
      <div className="flex h-40 items-center justify-center text-sm text-slate-500">
        Run the pipeline to see behavioral clusters.
      </div>
    )
  }

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between">
        <div>
          <h2 className="flex items-center gap-2 text-xl font-semibold text-white">
            <Shield size={18} className="text-indigo-400" /> Behavioral Clusters
          </h2>
          <p className="mt-1 text-sm text-slate-400">
            Aggregated behavioral groups derived from user activity patterns
          </p>
        </div>
        <div className="chip border border-white/10 bg-white/5 text-slate-300">
          <Users size={12} /> {clusters.length} clusters
        </div>
      </div>

      <ClusterScatterPlot users={users} onSelectUser={onSelectUser} />

      <div className="grid gap-3 lg:grid-cols-2">
        {clusters.map(cluster => (
          <article key={cluster.cluster_label} className="glass rounded-2xl border border-white/10 p-4 slide-up transition hover:border-white/20">
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="text-base font-semibold text-white">{cluster.description}</div>
                <div className="mt-1 text-[11px] uppercase tracking-widest text-slate-500">
                  Cluster {cluster.cluster_label}
                </div>
              </div>
              <span className="chip border border-white/10 bg-white/5 text-slate-300">
                {cluster.user_count} users
              </span>
            </div>

            <div className="mt-4">
              <div className="mb-1 flex items-center justify-between text-[11px] text-slate-500">
                <span>Avg Risk</span>
                <span className="text-slate-300">{Number(cluster.avg_risk_score).toFixed(1)}</span>
              </div>
              <div className="risk-bar">
                <div className={`risk-bar-fill bg-gradient-to-r ${riskGradient(cluster.avg_risk_score)}`} style={{ width: `${cluster.avg_risk_score}%` }} />
              </div>
            </div>

            <div className="mt-4 flex flex-wrap gap-2">
              {(cluster.top_flags || []).slice(0, 3).map(flag => (
                <span key={flag} className="chip border border-white/10 bg-white/5 text-[10px] text-slate-300">
                  {flag.replace(/_/g, ' ')}
                </span>
              ))}
              {(cluster.top_flags || []).length === 0 && (
                <span className="chip border border-white/10 bg-white/5 text-[10px] text-slate-500">
                  No dominant flags
                </span>
              )}
            </div>

            <div className="mt-4 flex items-center gap-3 text-xs text-slate-400">
              <span className="flex items-center gap-1.5"><span className={`h-2 w-2 rounded-full ${dotClass('critical')}`} /> {cluster.critical_count} critical</span>
              <span className="flex items-center gap-1.5"><span className={`h-2 w-2 rounded-full ${dotClass('high')}`} /> {cluster.high_count} high</span>
              <span className="flex items-center gap-1.5"><span className={`h-2 w-2 rounded-full ${dotClass('review')}`} /> {cluster.review_count} review</span>
            </div>
          </article>
        ))}
      </div>
    </div>
  )
}