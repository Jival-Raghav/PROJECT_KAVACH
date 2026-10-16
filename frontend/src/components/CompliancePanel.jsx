import { ShieldCheck, ShieldAlert, FileWarning } from 'lucide-react'

const FRAMEWORK_STYLE = {
  'NIST AC-2': { color: 'text-blue-300 border-blue-400/40 bg-blue-500/10',   icon: ShieldCheck },
  'NIST AC-6': { color: 'text-purple-300 border-purple-400/40 bg-purple-500/10', icon: ShieldAlert },
  'GDPR Art.32': { color: 'text-rose-300 border-rose-400/40 bg-rose-500/10', icon: FileWarning },
}

const SEV_BADGE = {
  HIGH:   'border-rose-400/40 bg-rose-500/10 text-rose-300',
  MEDIUM: 'border-orange-400/40 bg-orange-500/10 text-orange-300',
  LOW:    'border-yellow-400/30 bg-yellow-500/10 text-yellow-300',
}

export default function CompliancePanel({ users }) {
  const withGaps = users.filter(u => (u.compliance_gaps || []).length > 0)
  const totalGaps = users.reduce((s, u) => s + (u.compliance_gaps || []).length, 0)

  // Framework breakdown
  const fwCount = {}
  users.forEach(u => (u.compliance_gaps || []).forEach(g => {
    const fw = g.framework || 'Other'
    fwCount[fw] = (fwCount[fw] || 0) + 1
  }))

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between">
        <div>
          <h2 className="flex items-center gap-2 text-xl font-semibold text-white">
            <ShieldCheck size={18} className="text-indigo-400" /> Compliance Gaps
          </h2>
          <p className="mt-1 text-sm text-slate-400">
            {totalGaps} violations across {withGaps.length} users · NIST AC-2, AC-6, GDPR Art.32
          </p>
        </div>
      </div>

      {/* Framework summary */}
      {Object.keys(fwCount).length > 0 && (
        <div className="flex flex-wrap gap-2">
          {Object.entries(fwCount).map(([fw, count]) => {
            const s = FRAMEWORK_STYLE[fw] || { color: 'text-slate-300 border-white/20 bg-white/5', icon: ShieldCheck }
            const Icon = s.icon
            return (
              <div key={fw} className={`chip border ${s.color} gap-1.5 px-3 py-1.5`}>
                <Icon size={10} /> {fw}: {count}
              </div>
            )
          })}
        </div>
      )}

      {/* User cards */}
      <div className="space-y-3">
        {withGaps.length === 0 ? (
          <div className="flex h-40 items-center justify-center text-sm text-slate-500">
            No compliance gaps detected. Run the pipeline first.
          </div>
        ) : withGaps.map(user => (
          <article key={user.user_id} className="glass rounded-2xl border border-white/10 p-4 slide-up transition hover:border-white/20">
            <div className="flex items-center justify-between gap-4">
              <div>
                <div className="font-medium text-white">{user.username}</div>
                <div className="text-[11px] text-slate-500">{user.department} · {user.privilege_level} · <span className="mono">{user.user_id}</span></div>
              </div>
              <span className="chip border border-rose-400/40 bg-rose-500/10 text-rose-300 shrink-0">
                {user.compliance_gaps.length} gap{user.compliance_gaps.length !== 1 ? 's' : ''}
              </span>
            </div>

            <div className="mt-3 space-y-2">
              {(user.compliance_gaps || []).map((gap, i) => {
                const s = FRAMEWORK_STYLE[gap.framework] || { color: 'text-slate-400 border-white/15 bg-white/5', icon: ShieldAlert }
                const Icon = s.icon
                const sev = SEV_BADGE[gap.severity] || SEV_BADGE.LOW
                return (
                  <div key={i} className="rounded-xl border border-white/8 bg-white/4 p-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`chip border ${s.color}`}><Icon size={9} /> {gap.framework}</span>
                      <span className={`chip border ${sev}`}>{gap.severity}</span>
                      <span className="text-[11px] text-slate-400">{gap.control}</span>
                    </div>
                    <p className="mt-2 text-xs leading-relaxed text-slate-300">{gap.description}</p>
                    {gap.recommendation && (
                      <p className="mt-1.5 text-[11px] text-indigo-400 italic">→ {gap.recommendation}</p>
                    )}
                  </div>
                )
              })}
            </div>
          </article>
        ))}
      </div>
    </div>
  )
}
