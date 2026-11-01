import { useState } from 'react'
import {
  AlertTriangle, FileText, Flag, Loader2, ListChecks, Megaphone, Radiation, Sparkles, Clock,
} from 'lucide-react'
import { getIncidentReport } from '../../api'
import { prettifyText } from './format'

const SECTION_ICON = [
  [/what happened/i, Clock],
  [/kill.?chain/i, Flag],
  [/alerts? merged/i, Megaphone],
  [/reach/i, Radiation],
  [/recommended|action/i, ListChecks],
]
const iconFor = title => (SECTION_ICON.find(([re]) => re.test(title))?.[1]) || FileText

// Minimal, safe renderer: React escapes all text, so log content cannot inject HTML.
function inline(text) {
  return prettifyText(text).split(/(\*\*[^*]+\*\*|`[^`]+`)/g).map((p, i) => {
    if (p.startsWith('**')) return <b key={i}>{p.slice(2, -2)}</b>
    if (p.startsWith('`')) return <code key={i}>{p.slice(1, -1)}</code>
    return p
  })
}

function parseReport(markdown) {
  const sections = []
  let headline = ''
  let current = null
  markdown.split('\n').forEach(raw => {
    const line = raw.trim()
    if (line.startsWith('# ')) headline = line.slice(2)
    else if (line.startsWith('## ')) {
      current = { title: line.slice(3), blocks: [] }
      sections.push(current)
    } else if (line) {
      if (!current) {
        current = { title: '', blocks: [] }
        sections.push(current)
      }
      const bullet = line.startsWith('- ')
      const last = current.blocks[current.blocks.length - 1]
      if (bullet && last?.items) last.items.push(line.slice(2))
      else if (bullet) current.blocks.push({ items: [line.slice(2)] })
      else current.blocks.push({ text: line.replace(/^_|_$/g, '') })
    }
  })
  return { headline, sections }
}

export default function ReportTab({ incidentId, report, onReport }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const rewrite = () => {
    setBusy(true)
    setError('')
    getIncidentReport(incidentId, true).then(onReport).catch(e => setError(String(e)))
      .finally(() => setBusy(false))
  }
  if (!report) {
    return (
      <div className="card kc-empty-state">
        <FileText size={24} />
        <b>No report for this incident</b>
      </div>
    )
  }
  const { headline, sections } = parseReport(report.body_markdown)
  return (
    <div className="kc-tab-page">
      <div className="kc-tab-intro kc-intro-row">
        <div>
          <h3>Incident report</h3>
          <p>A written summary to share with people who were not part of the investigation.</p>
        </div>
        <button className="btn-ghost" onClick={rewrite} disabled={busy}>
          {busy ? <Loader2 size={13} className="spin-slow" /> : <Sparkles size={13} />} Rewrite with AI
        </button>
      </div>
      {error && <div className="kc-error"><AlertTriangle size={14} /> {error}</div>}

      <article className="kc-report-doc">
        {headline && (
          <header className="card kc-report-head">
            <FileText size={18} className="kc-report-head-icon" />
            <h2>{inline(headline)}</h2>
          </header>
        )}
        {sections.map((s, i) => {
          const Icon = iconFor(s.title)
          return (
            <section key={i} className="card kc-report-section">
              {s.title && <h4><Icon size={15} className="kc-report-section-icon" /> {inline(s.title)}</h4>}
              {s.blocks.map((b, j) => (b.items
                ? <ul key={j}>{b.items.map((it, k) => <li key={k}>{inline(it)}</li>)}</ul>
                : <p key={j}>{inline(b.text)}</p>))}
            </section>
          )
        })}
      </article>
    </div>
  )
}
