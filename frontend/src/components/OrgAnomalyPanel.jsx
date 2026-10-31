export default function OrgAnomalyPanel({ anomalies }) {
  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-2xl font-semibold text-white">Org Anomalies</h2>
        <p className="mt-1 text-sm text-slate-400">Department-level outliers surfaced by the pipeline.</p>
      </div>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {anomalies.map(item => (
          <article key={item.user_id} className="rounded-3xl border border-white/10 bg-white/5 p-4">
            <div className="text-sm font-semibold text-white">{item.username}</div>
            <div className="mt-1 text-xs uppercase tracking-[0.3em] text-slate-500">{item.department}</div>
            <div className="mt-3 rounded-2xl bg-rose-500/10 p-3 text-sm text-rose-100">
              {item.org_anomaly?.reason || 'No anomaly reason available.'}
            </div>
          </article>
        ))}
      </div>
    </div>
  )
}
