import { postFeedback } from '../api'

export default function FeedbackButtons({ user }) {
  if (!user) {
    return null
  }

  return (
    <section className="rounded-[2rem] border border-white/10 bg-slate-950/80 p-5">
      <div className="text-xs uppercase tracking-[0.35em] text-slate-500">Feedback</div>
      <div className="mt-4 flex gap-3">
        <button
          onClick={() => postFeedback(user.user_id, 'suppress', 'Analyst suppressed this alert')}
          className="rounded-2xl bg-emerald-500 px-4 py-2 text-sm font-semibold text-slate-950"
        >
          Suppress
        </button>
        <button
          onClick={() => postFeedback(user.user_id, 'unflag', 'Analyst restored this alert')}
          className="rounded-2xl bg-white/10 px-4 py-2 text-sm font-semibold text-white"
        >
          Unflag
        </button>
      </div>
    </section>
  )
}
