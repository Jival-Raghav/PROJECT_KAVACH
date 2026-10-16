import { useEffect, useState } from 'react'
import { streamNarrative } from '../api'

export default function NarrativePanel({ user }) {
  const [narrative, setNarrative] = useState('')

  useEffect(() => {
    setNarrative('')
    if (!user?.user_id) {
      return
    }

    const source = streamNarrative(
      user.user_id,
      chunk => {
        setNarrative(current => `${current}${chunk}\n`)
      },
      () => {}
    )

    return () => source?.close?.()
  }, [user?.user_id])

  return (
    <section className="rounded-[2rem] border border-white/10 bg-slate-950/80 p-5">
      <div className="text-xs uppercase tracking-[0.35em] text-slate-500">Narrative</div>
      <pre className="mt-3 min-h-40 whitespace-pre-wrap rounded-2xl border border-white/10 bg-white/5 p-4 text-sm leading-6 text-slate-200">
        {user ? narrative || 'Narrative will stream here when a user is selected.' : 'Select a user to generate an explanation.'}
      </pre>
    </section>
  )
}
