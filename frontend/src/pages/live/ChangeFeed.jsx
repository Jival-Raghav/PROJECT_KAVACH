import { useEffect, useState } from 'react'
import { getLiveChanges } from '../../api'
import { useRun } from '../../run'

function Headline({ text, onOpen }) {
  const parts = text.split(/(#\d+)/g)
  return (
    <>
      {parts.map((p, i) => /^#\d+$/.test(p)
        ? <button key={i} type="button" className="live-link" onClick={() => onOpen(Number(p.slice(1)))}>{p}</button>
        : <span key={i}>{p}</span>)}
    </>
  )
}

export default function ChangeFeed({ onOpen }) {
  const { runId, generation } = useRun()
  const [entries, setEntries] = useState([])

  useEffect(() => {
    let off = false
    getLiveChanges(runId).then(c => { if (!off) setEntries(c) }).catch(() => {})
    return () => { off = true }
  }, [runId, generation])

  const shown = entries.filter(e => e.headlines?.length).slice(-8).reverse()
  return (
    <section className="card change-feed" aria-label="Recent changes">
      <div className="change-feed-head">Recent changes</div>
      {shown.length === 0 ? (
        <div className="kc-muted">No changes yet.</div>
      ) : shown.map(e => (
        <div className="change-feed-item" key={e.generation}>
          <div className="change-feed-meta">
            <span className="chip kc-chip mono">update {e.generation}</span>
            <span className="kc-muted mono">{e.at ? new Date(e.at).toLocaleTimeString() : ''}</span>
          </div>
          <ul>
            {(e.headlines || []).map((h, i) => <li key={i}><Headline text={h} onOpen={onOpen} /></li>)}
          </ul>
        </div>
      ))}
    </section>
  )
}
