import { useState } from 'react'
import { CheckCircle2, Send, Loader2, RotateCcw } from 'lucide-react'
import { postFeedback } from '../api'

export default function FeedbackButtons({ user }) {
  const [loading, setLoading] = useState(false)
  const [note, setNote] = useState('')
  const [showNote, setShowNote] = useState(false)
  const [submitted, setSubmitted] = useState(false)

  if (!user) return null

  const handleFeedback = async () => {
    if (!showNote) {
      setShowNote(true)
      return
    }
    setLoading(true)
    try {
      await postFeedback(user.user_id, 'suppress', note)
      setNote('')
      setShowNote(false)
      setSubmitted(true)
      setTimeout(() => setSubmitted(false), 3000)
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  const handleUndo = async () => {
    setLoading(true)
    try {
      await postFeedback(user.user_id, 'unflag', '')
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  if (user.suppressed) {
    return (
      <section className="glass rounded-2xl border border-white/10 p-5 slide-up">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <CheckCircle2 size={16} className="text-emerald-400" />
            <span className="text-sm font-medium text-emerald-300">Marked as False Positive ✓</span>
          </div>
          <button
            onClick={handleUndo}
            disabled={loading}
            className="flex items-center gap-1 rounded-lg border border-slate-500/30 bg-slate-500/10 px-3 py-1.5 text-xs text-slate-300 transition hover:border-slate-500/50 hover:bg-slate-500/20 disabled:opacity-50"
          >
            {loading ? <Loader2 size={12} className="spin-slow" /> : <RotateCcw size={12} />}
            Undo
          </button>
        </div>
      </section>
    )
  }

  return (
    <section className="glass rounded-2xl border border-white/10 p-5 slide-up">
      <div className="mb-3 text-[11px] uppercase tracking-widest text-slate-500">Feedback</div>

      {submitted && (
        <div className="mb-4 rounded-xl border border-emerald-400/40 bg-emerald-500/10 p-3 text-sm text-emerald-300">
          Feedback recorded — this finding will be suppressed
        </div>
      )}

      {!showNote ? (
        <button
          onClick={handleFeedback}
          className="w-full flex items-center justify-center gap-2 rounded-xl border border-emerald-500/30 bg-emerald-500/10 py-2.5 text-xs font-medium text-emerald-300 transition hover:bg-emerald-500/20"
        >
          <CheckCircle2 size={14} /> False Positive? Give Feedback
        </button>
      ) : (
        <div className="slide-up space-y-2">
          <textarea
            value={note}
            onChange={e => setNote(e.target.value)}
            placeholder="Why is this a false positive?"
            className="w-full resize-none rounded-xl border border-white/10 bg-black/30 p-3 text-sm text-slate-200 placeholder-slate-600 outline-none focus:border-cyan-500/40 focus:ring-1 focus:ring-cyan-500/20"
            rows={3}
            autoFocus
          />
          <div className="flex gap-2">
            <button
              onClick={() => { setShowNote(false); setNote('') }}
              className="rounded-xl border border-white/10 px-4 py-2 text-xs text-slate-400 hover:bg-white/5 hover:text-white"
            >
              Cancel
            </button>
            <button
              onClick={handleFeedback}
              disabled={loading || !note.trim()}
              className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-emerald-600 py-2 text-xs font-medium text-white transition hover:bg-emerald-500 disabled:opacity-50"
            >
              {loading ? <Loader2 size={14} className="spin-slow" /> : <Send size={14} />}
              Submit
            </button>
          </div>
        </div>
      )}
    </section>
  )
}
