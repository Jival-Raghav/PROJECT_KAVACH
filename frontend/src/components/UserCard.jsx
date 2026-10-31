export default function UserCard({ user, onClose }) {
  if (!user) {
    return null
  }

  return (
    <section className="rounded-[2rem] border border-white/10 bg-slate-950/80 p-5 shadow-2xl shadow-black/30 backdrop-blur">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="text-xs uppercase tracking-[0.35em] text-slate-500">Selected User</div>
          <h2 className="mt-2 text-2xl font-semibold text-white">{user.username}</h2>
          <p className="text-sm text-slate-400">{user.job_title}</p>
        </div>
        <button onClick={onClose} className="rounded-full border border-white/10 px-3 py-1 text-sm text-slate-300 hover:bg-white/5">
          Close
        </button>
      </div>

      <dl className="mt-5 grid grid-cols-2 gap-4 text-sm">
        <Field label="Department" value={user.department} />
        <Field label="Privilege" value={user.privilege_level} />
        <Field label="Risk Score" value={Number(user.risk_score).toFixed(1)} />
        <Field label="Events" value={user.event_count} />
        <Field label="Cluster" value={user.cluster_description} />
        <Field label="Suppressed" value={String(user.suppressed)} />
      </dl>
    </section>
  )
}

function Field({ label, value }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-white/5 p-3">
      <dt className="text-[11px] uppercase tracking-[0.3em] text-slate-500">{label}</dt>
      <dd className="mt-2 text-sm text-slate-100">{value}</dd>
    </div>
  )
}
