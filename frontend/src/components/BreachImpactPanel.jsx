import { AlertTriangle, Fingerprint, Network, Database, ShieldAlert, Sparkles, MessageSquareWarning } from 'lucide-react'

export default function BreachImpactPanel({ user }) {
  if (!user?.narrative?.breach_impact) return null

  // We can try to parse the LLM narrative if it returned a list of systems,
  // but usually it's just a paragraph. We'll present it nicely.
  return (
    <section className="glass rounded-2xl border border-white/10 p-5 slide-up">
      <div className="flex items-center gap-2 text-[11px] uppercase tracking-widest text-slate-500">
        <AlertTriangle size={12} className="text-rose-400" /> Breach Impact
      </div>
      <div className="mt-3">
        <p className="text-sm leading-relaxed text-slate-300">
          {user.narrative.breach_impact}
        </p>
      </div>
      {/* If it was a real high risk, show some mocked "systems at risk" based on their access */}
      {user.risk_score >= 60 && user.systems_access && (
        <div className="mt-4 border-t border-white/5 pt-4">
          <div className="mb-2 text-[10px] uppercase tracking-widest text-slate-500">Exposed Systems</div>
          <div className="flex flex-wrap gap-2">
            {(user.systems_access || []).map(sys => {
              const iconMap = {
                'AWS': <Database size={10} />,
                'Azure': <Network size={10} />,
                'Okta': <Fingerprint size={10} />,
                'PROD': <ShieldAlert size={10} />
              }
              const Icon = Object.entries(iconMap).find(([k]) => sys.toUpperCase().includes(k))?.[1] || <Sparkles size={10} />
              return (
                <div key={sys} className="flex items-center gap-1.5 rounded-lg border border-rose-500/20 bg-rose-500/10 px-2.5 py-1.5 text-xs text-rose-200">
                  {Icon} {sys}
                </div>
              )
            })}
          </div>
        </div>
      )}
    </section>
  )
}
