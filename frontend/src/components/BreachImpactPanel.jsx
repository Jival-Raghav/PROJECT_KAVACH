export default function BreachImpactPanel({ user }) {
  return (
    <section className="rounded-[2rem] border border-white/10 bg-slate-950/80 p-5">
      <div className="text-xs uppercase tracking-[0.35em] text-slate-500">Breach Impact</div>
      <div className="mt-3 rounded-2xl border border-white/10 bg-white/5 p-4 text-sm leading-6 text-slate-200">
        {user?.narrative?.breach_impact || 'The breach impact summary appears here after narrative generation.'}
      </div>
    </section>
  )
}
