import { useState } from 'react'
import { CheckCircle2, Send, Loader2, RotateCcw } from 'lucide-react'
import { postFeedback } from '../api'

export default function FeedbackButtons({ user }) {
  const [loading,   setLoading]   = useState(false)
  const [note,      setNote]      = useState('')
  const [showNote,  setShowNote]  = useState(false)
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

  /* ── Suppressed state ─────────────────────────── */
  if (user.suppressed) {
    return (
      <section className="card slide-up" style={{ padding: 14, flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
            <CheckCircle2 size={15} style={{ color: 'var(--c-normal)', flexShrink: 0 }} />
            <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--c-normal)' }}>Marked as False Positive</span>
          </div>
          <button
            onClick={handleUndo}
            disabled={loading}
            className="btn-ghost"
          >
            {loading ? <Loader2 size={12} className="spin-slow" /> : <RotateCcw size={12} />}
            Undo
          </button>
        </div>
      </section>
    )
  }

  /* ── Default feedback section ─────────────────── */
  return (
    <section className="card slide-up" style={{ padding: 14, flexShrink: 0 }}>
      <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.09em', color: 'var(--text-muted)', marginBottom: 10 }}>
        Analyst Feedback
      </div>

      {submitted && (
        <div style={{ marginBottom: 10, borderRadius: 4, border: '1px solid var(--c-normal-bd)', background: 'var(--c-normal-bg)', padding: '8px 10px', fontSize: 12, color: 'var(--c-normal)' }}>
          Feedback recorded — this finding will be suppressed
        </div>
      )}

      {!showNote ? (
        <button
          onClick={handleFeedback}
          className="btn-ghost"
          style={{ width: '100%', justifyContent: 'center', height: 34 }}
        >
          <CheckCircle2 size={13} /> False Positive? Give Feedback
        </button>
      ) : (
        <div className="slide-up" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <textarea
            value={note}
            onChange={e => setNote(e.target.value)}
            placeholder="Why is this a false positive?"
            style={{
              width: '100%', resize: 'none', padding: '8px 10px', fontSize: 12,
              color: 'var(--text-primary)', background: 'var(--surface-mid)',
              border: '1px solid var(--border)', borderRadius: 4, outline: 'none',
              fontFamily: 'inherit',
            }}
            rows={3}
            autoFocus
            onFocus={e => { e.target.style.borderColor = 'var(--sg-red-border)' }}
            onBlur={e  => { e.target.style.borderColor = 'var(--border)' }}
          />
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              onClick={() => { setShowNote(false); setNote('') }}
              className="btn-ghost"
              style={{ flex: 1, justifyContent: 'center' }}
            >
              Cancel
            </button>
            <button
              onClick={handleFeedback}
              disabled={loading || !note.trim()}
              className="btn-primary"
              style={{ flex: 2, justifyContent: 'center' }}
            >
              {loading ? <Loader2 size={13} className="spin-slow" /> : <Send size={13} />}
              Submit
            </button>
          </div>
        </div>
      )}
    </section>
  )
}
