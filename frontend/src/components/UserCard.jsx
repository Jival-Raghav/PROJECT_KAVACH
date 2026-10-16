import { Shield, ShieldAlert, Cpu, Database, KeyRound, Building2, Calendar, FileWarning } from 'lucide-react'

export default function UserCard({ user, onClose }) {
  if (!user) return null

  const isHighRisk = user.risk_score >= 60

  return (
    <section className="glass rounded-2xl border border-white/10 p-5 shadow-2xl slide-up relative overflow-hidden">
      {/* Background glow if high risk */}
      {isHighRisk && <div className="absolute -right-20 -top-20 h-40 w-40 rounded-full bg-rose-500/20 blur-3xl pointer-events-none" />}

      <div className="flex items-start justify-between gap-4 relative">
        <div className="flex gap-4">
          <div className={`flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl border ${isHighRisk ? 'border-rose-500/30 bg-rose-500/10 text-rose-400' : 'border-cyan-500/30 bg-cyan-500/10 text-cyan-400'}`}>
            {isHighRisk ? <ShieldAlert size={24} /> : <Shield size={24} />}
          </div>
          <div>
            <div className="text-[10px] uppercase tracking-[0.35em] text-slate-500">Target Profile</div>
            <h2 className="text-xl font-bold text-white tracking-tight">{user.username}</h2>
            <p className="text-xs text-slate-400 font-mono mt-0.5">{user.user_id}</p>
          </div>
        </div>
        <button onClick={onClose} className="rounded-full bg-white/5 p-2 text-slate-400 transition hover:bg-white/10 hover:text-white">
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12"></path></svg>
        </button>
      </div>

      <div className="mt-5 grid grid-cols-2 gap-3">
        <Field icon={Building2} label="Department" value={user.department} />
        <Field icon={KeyRound} label="Privilege" value={user.privilege_level} />
        <Field icon={Database} label="Cluster" value={user.cluster_description || 'Unknown'} />
        <Field icon={FileWarning} label="Events" value={`${user.event_count || 0} analysed`} />
        {user.last_login && <Field icon={Calendar} label="Last Login" value={new Date(user.last_login).toLocaleDateString()} />}
        {user.days_inactive !== undefined && <Field icon={Calendar} label="Days Inactive" value={user.days_inactive} highlight={user.days_inactive > 30} />}
      </div>

      {user.systems_access && user.systems_access.length > 0 && (
        <div className="mt-4 pt-4 border-t border-white/5">
          <div className="mb-2 text-[10px] uppercase tracking-widest text-slate-500">Provisioned Systems</div>
          <div className="flex flex-wrap gap-1.5">
            {user.systems_access.map(sys => (
              <span key={sys} className="chip bg-white/5 text-slate-300 border-white/10">{sys}</span>
            ))}
          </div>
        </div>
      )}
    </section>
  )
}

function Field({ icon: Icon, label, value, highlight }) {
  return (
    <div className={`rounded-xl border border-white/5 p-3 flex flex-col gap-1.5 ${highlight ? 'bg-rose-500/5 border-rose-500/20' : 'bg-white/4'}`}>
      <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-widest text-slate-500">
        <Icon size={10} className={highlight ? 'text-rose-400' : ''} /> {label}
      </div>
      <div className={`text-sm font-medium ${highlight ? 'text-rose-300' : 'text-slate-200'}`}>
        {value}
      </div>
    </div>
  )
}
