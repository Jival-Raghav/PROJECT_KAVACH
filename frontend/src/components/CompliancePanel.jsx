export default function CompliancePanel({ users }) {
  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-2xl font-semibold text-white">Compliance</h2>
        <p className="mt-1 text-sm text-slate-400">Stubbed control gaps are displayed once the backend computes them.</p>
      </div>
      <div className="grid gap-4">
        {users.map(user => (
          <article key={user.user_id} className="rounded-3xl border border-white/10 bg-white/5 p-4">
            <div className="flex items-center justify-between gap-4">
              <div>
                <div className="font-semibold text-white">{user.username}</div>
                <div className="text-sm text-slate-400">{user.department}</div>
              </div>
              <div className="text-sm text-slate-300">{(user.compliance_gaps || []).length} gaps</div>
            </div>
          </article>
        ))}
      </div>
    </div>
  )
}
