export default function RiskTable({ users, onSelectUser }) {
  return (
    <div className="overflow-x-auto">
      <table className="min-w-full border-separate border-spacing-0 text-left text-sm">
        <thead>
          <tr className="text-slate-400">
            {['Username', 'Department', 'Privilege', 'Risk Score', 'Flags', 'Cluster', 'Actions'].map(column => (
              <th key={column} className="border-b border-white/10 px-4 py-3 font-medium uppercase tracking-[0.2em]">
                {column}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {users.map(user => (
            <tr key={user.user_id} className="border-b border-white/5 text-slate-200 hover:bg-white/5">
              <td className="px-4 py-4 font-medium text-white">{user.username}</td>
              <td className="px-4 py-4">{user.department}</td>
              <td className="px-4 py-4">{user.privilege_level}</td>
              <td className="px-4 py-4">
                <span className={`rounded-full px-3 py-1 text-xs font-semibold ${riskClass(user.risk_score)}`}>{Number(user.risk_score).toFixed(1)}</span>
              </td>
              <td className="px-4 py-4">{(user.flags || []).length}</td>
              <td className="px-4 py-4">{user.cluster_description}</td>
              <td className="px-4 py-4">
                <button
                  onClick={() => onSelectUser(user)}
                  className="rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-xs font-medium text-white transition hover:bg-white/10"
                >
                  Inspect
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function riskClass(score) {
  if (score >= 80) {
    return 'bg-rose-500/20 text-rose-200'
  }
  if (score >= 60) {
    return 'bg-orange-500/20 text-orange-200'
  }
  if (score >= 40) {
    return 'bg-amber-400/20 text-amber-100'
  }
  return 'bg-emerald-500/20 text-emerald-100'
}
