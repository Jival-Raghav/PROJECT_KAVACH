import { useState } from 'react'
import { CheckCircle2, XCircle, AlertCircle, Send, Loader2 } from 'lucide-react'
import { postFeedback } from '../api'

export default function FeedbackButtons({ user }) {
  const [loading, setLoading] = useState(false)
  const [note, setNote] = useState('')
  const [showNote, setShowNote] = useState(false)
  const [actionType, setActionType] = useState(null)

  if (!user || !user.narrative) return null

  const handleAction = async (action) => {
    if (!showNote) {
      setActionType(action)
      setShowNote(true)
      return
    }
    setLoading(true)
    try {
      await postFeedback(user.user_id, actionType, note)
      setShowNote(false)
      setNote('')
      // In a real app we'd refresh the user list here or show a toast
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  return (
    <section className="glass rounded-2xl border border-white/10 p-5 slide-up">
      <div className="mb-3 text-[11px] uppercase tracking-widest text-slate-500">Security Action</div>

      {!showNote ? (
        <div className="grid grid-cols-2 gap-2">
          <button
            onClick={() => handleAction('suppress')}
            className="flex items-center justify-center gap-2 rounded-xl border border-emerald-500/30 bg-emerald-500/10 py-2.5 text-xs font-medium text-emerald-300 transition hover:bg-emerald-500/20"
          >
            <CheckCircle2 size={14} /> Legitimate (Suppress)
          </button>
          <button
            onClick={() => handleAction('escalate')}
            className="flex items-center justify-center gap-2 rounded-xl border border-rose-500/30 bg-rose-500/10 py-2.5 text-xs font-medium text-rose-300 transition hover:bg-rose-500/20"
          >
            <AlertCircle size={14} /> Escalate (Investigate)
          </button>
        </div>
      ) : (
        <div className="slide-up">
          <textarea
            value={note}
            onChange={e => setNote(e.target.value)}
            placeholder={`Add a note for why you are ${actionType === 'suppress' ? 'suppressing' : 'escalating'} this...`}
            className="w-full resize-none rounded-xl border border-white/10 bg-black/30 p-3 text-sm text-slate-200 placeholder-slate-600 outline-none focus:border-cyan-500/40 focus:ring-1 focus:ring-cyan-500/20"
            rows={3}
            autoFocus
          />
          <div className="mt-2 flex gap-2">
            <button
              onClick={() => { setShowNote(false); setNote('') }}
              className="rounded-xl border border-white/10 px-4 py-2 text-xs text-slate-400 hover:bg-white/5 hover:text-white"
            >
              Cancel
            </button>
            <button
              onClick={() => handleAction(actionType)}
              disabled={loading || !note.trim()}
              className={`flex flex-1 items-center justify-center gap-2 rounded-xl py-2 text-xs font-medium text-white transition ${
                actionType === 'suppress'
                  ? 'bg-emerald-600 hover:bg-emerald-500'
                  : 'bg-rose-600 hover:bg-rose-500'
              } disabled:opacity-50`}
            >
              {loading ? <Loader2 size={14} className="spin-slow" /> : <Send size={14} />}
              Confirm {actionType === 'suppress' ? 'Suppression' : 'Escalation'}
            </button>
          </div>
        </div>
      )}
    </section>
  )
}
