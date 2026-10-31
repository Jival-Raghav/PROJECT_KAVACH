import { useEffect, useRef, useState } from 'react'
import * as d3 from 'd3'
import { ArrowLeft, Loader2, Sparkles } from 'lucide-react'
import { getIncident, getIncidentReport, getIncidentReview } from '../api'
import { SeverityBadge, StageStrip } from './KillChain'
import { ActorTable } from './Actors'
import { ControlTable } from './ControlFindings'

const KIND_COLOR = {
  external_ip: '#C8412F', host: '#0369A1', user: '#B45309', firewall: '#7C3AED', domain: '#6B6E68',
}

function PathGraph({ path }) {
  const ref = useRef(null)
  useEffect(() => {
    if (!path || !ref.current) return
    const width = ref.current.clientWidth || 720
    const height = 380
    const svg = d3.select(ref.current).attr('viewBox', `0 0 ${width} ${height}`)
    svg.selectAll('*').remove()
    const nodes = path.nodes.map(n => ({ ...n }))
    // One line per node pair; its label lists the steps in time order (1. T1595 → 2. T1190 …)
    const order = [...new Set(path.edges.map(e => e.technique_id))]
    const byPair = new Map()
    path.edges.forEach(e => {
      const k = `${e.source}|${e.target}`
      if (!byPair.has(k)) byPair.set(k, { source: e.source, target: e.target, techs: [] })
      const l = byPair.get(k)
      if (!l.techs.includes(e.technique_id)) l.techs.push(e.technique_id)
    })
    const links = [...byPair.values()].map(l => ({
      ...l, label: l.techs.map(t => `${order.indexOf(t) + 1}. ${t}`).join('  →  '),
    }))

    svg.append('defs').append('marker').attr('id', 'kc-arrow').attr('viewBox', '0 -5 10 10')
      .attr('refX', 18).attr('markerWidth', 7).attr('markerHeight', 7).attr('orient', 'auto')
      .append('path').attr('d', 'M0,-5L10,0L0,5').attr('fill', 'var(--text-muted)')

    const g = svg.append('g')
    svg.call(d3.zoom().scaleExtent([0.3, 3]).on('zoom', ev => g.attr('transform', ev.transform)))

    const sim = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id(d => d.id).distance(links.length > 8 ? 90 : 220))
      .force('charge', d3.forceManyBody().strength(-260))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collide', d3.forceCollide(26))

    const link = g.append('g').selectAll('line').data(links).join('line')
      .attr('stroke', 'var(--text-muted)').attr('stroke-opacity', 0.55).attr('stroke-width', 1.4)
      .attr('marker-end', 'url(#kc-arrow)')
    const linkLabel = g.append('g').selectAll('text').data(links).join('text')
      .attr('class', 'kc-edge-label').attr('text-anchor', 'middle').text(d => d.label)
    const node = g.append('g').selectAll('g').data(nodes).join('g')
      .call(d3.drag()
        .on('start', (ev, d) => { if (!ev.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y })
        .on('drag', (ev, d) => { d.fx = ev.x; d.fy = ev.y })
        .on('end', (ev, d) => { if (!ev.active) sim.alphaTarget(0); d.fx = null; d.fy = null }))
    node.append('circle').attr('r', d => d.kind === 'firewall' ? 13 : 10)
      .attr('fill', d => KIND_COLOR[d.kind] || '#888').attr('stroke', 'var(--surface)').attr('stroke-width', 2)
    node.append('text').attr('class', 'kc-node-label').attr('dy', 24).attr('text-anchor', 'middle')
      .text(d => d.label)
    node.append('title').text(d => `${d.kind}: ${d.label}${d.segment ? ` (${d.segment})` : ''}`)

    sim.on('tick', () => {
      link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x).attr('y2', d => d.target.y)
      linkLabel.attr('x', d => (d.source.x + d.target.x) / 2).attr('y', d => (d.source.y + d.target.y) / 2 - 4)
      node.attr('transform', d => `translate(${d.x},${d.y})`)
    })
    return () => sim.stop()
  }, [path])
  return (
    <div>
      <svg ref={ref} className="kc-graph" />
      <div className="kc-legend">
        {Object.entries(KIND_COLOR).map(([k, c]) => (
          <span key={k}><i style={{ background: c }} />{k.replace('_', ' ')}</span>
        ))}
      </div>
    </div>
  )
}

function Markdown({ text }) {
  // Minimal, safe renderer: headings, bullets, bold, inline code. No HTML injection.
  const inline = s => s.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).map((p, i) =>
    p.startsWith('**') ? <b key={i}>{p.slice(2, -2)}</b>
      : p.startsWith('`') ? <code key={i}>{p.slice(1, -1)}</code> : p)
  return (
    <div className="kc-md">
      {text.split('\n').map((line, i) => {
        if (line.startsWith('# ')) return <h3 key={i}>{inline(line.slice(2))}</h3>
        if (line.startsWith('## ')) return <h4 key={i}>{inline(line.slice(3))}</h4>
        if (line.startsWith('- ')) return <div key={i} className="kc-md-li">• {inline(line.slice(2))}</div>
        if (!line.trim()) return <div key={i} className="kc-md-gap" />
        return <p key={i}>{inline(line.replace(/^_|_$/g, ''))}</p>
      })}
    </div>
  )
}

const REVIEW_SOURCE = { llm: 'live LLM', cached: 'saved LLM answer', template: 'built-in template' }

function Arguments({ title, items, evidence }) {
  const text = Object.fromEntries(evidence.map(e => [e.id, e.text]))
  return (
    <div>
      <h4>{title}</h4>
      {items.map((a, i) => (
        <div key={i} className="kc-md-li">
          • {a.text}{' '}
          {a.evidence.map(id => <span key={id} className="chip kc-chip mono" title={text[id]}>{id}</span>)}
        </div>
      ))}
    </div>
  )
}

function Review({ incidentId, initial }) {
  const [review, setReview] = useState(initial)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const runLive = () => {
    setBusy(true)
    setError('')
    getIncidentReview(incidentId, true).then(setReview).catch(e => setError(String(e)))
      .finally(() => setBusy(false))
  }

  if (!review) return null
  const v = review.verdict
  return (
    <section className="card kc-section">
      <div className="kc-section-head">
        <h3>Prosecutor vs Devil's Advocate</h3>
        <button className="btn-ghost" onClick={runLive} disabled={busy}>
          {busy ? <Loader2 size={13} className="spin-slow" /> : <Sparkles size={13} />} Run live review
        </button>
      </div>
      {error && <div className="kc-error">{error}</div>}
      {review.injection_flags?.length > 0 && (
        <div className="kc-error">Suspected prompt injection redacted in {review.injection_flags.join(', ')}.</div>
      )}
      <Arguments title="Prosecutor" items={review.prosecution} evidence={review.evidence} />
      <Arguments title="Devil's Advocate" items={review.defence} evidence={review.evidence} />
      <h4>Verdict: {v.final_priority} priority{v.lowered ? ` (lowered from ${v.risk_level})` : ''}</h4>
      <p>{v.reason} The incident stays on the board either way.</p>
      {v.verify.length > 0 && (
        <div>
          <b>To confirm:</b>
          {v.verify.map(q => <div key={q} className="kc-md-li">• {q}</div>)}
        </div>
      )}
      <div className="kc-muted">
        Written by: {REVIEW_SOURCE[review.generated_by] || review.generated_by}
        {review.note ? ` · ${review.note}` : ''}. The verdict is computed by a fixed rule, not by the LLM.
      </div>
    </section>
  )
}

export default function IncidentDetail({ incidentId, onBack }) {
  const [inc, setInc] = useState(null)
  const [report, setReport] = useState(null)
  const [aiBusy, setAiBusy] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    setInc(null)
    getIncident(incidentId).then(d => { setInc(d); setReport(d.report) }).catch(e => setError(String(e)))
  }, [incidentId])

  const rewrite = () => {
    setAiBusy(true)
    getIncidentReport(incidentId, true).then(setReport).catch(e => setError(String(e)))
      .finally(() => setAiBusy(false))
  }

  if (error) return <div className="kc-error">{error}</div>
  if (!inc) return <div className="kc-empty"><Loader2 size={16} className="spin-slow" /> Loading incident…</div>

  return (
    <div className="kc-page">
      <div className="kc-detail-head">
        <button className="btn-ghost" onClick={onBack}><ArrowLeft size={13} /> All incidents</button>
        <div className="kc-detail-title">
          <h2>#{inc.incident_id} · {inc.title}</h2>
          <div className="kc-detail-meta">
            <SeverityBadge severity={inc.severity} score={inc.risk_score} />
            <span>{inc.raw_alert_count.toLocaleString()} raw alerts merged into {inc.detection_count} detection(s)</span>
            <span className="kc-muted">{inc.first_seen.replace('T', ' ').slice(0, 19)} → {inc.last_seen.replace('T', ' ').slice(0, 19)}</span>
          </div>
          <StageStrip stages={inc.stages} />
        </div>
      </div>

      <div className="kc-grid">
        <section className="card kc-section">
          <h3>Timeline</h3>
          <ol className="kc-timeline">
            {inc.timeline.map(s => (
              <li key={s.detection_id} className={`outcome-${s.outcome}`}>
                <div className="kc-tl-time mono">{s.ts.replace('T', ' ').slice(0, 19)}</div>
                <div className="kc-tl-body">
                  <div><span className="chip kc-chip mono">{s.technique_id}</span> <b>{s.technique_name}</b></div>
                  <div className="kc-muted">{s.stage} · {s.tactic} · {s.event_count.toLocaleString()} events · {s.outcome}</div>
                  <div className="kc-tl-desc">{s.description}</div>
                </div>
              </li>
            ))}
          </ol>
        </section>

        <section className="card kc-section">
          <h3>Attack path</h3>
          <PathGraph path={inc.path} />
        </section>

        <section className="card kc-section">
          <h3>What they can reach next</h3>
          <p className="kc-reach-summary">{inc.reach.summary}</p>
          {inc.reach.targets.length > 0 && (
            <table className="kc-table static compact">
              <thead><tr><th>Target</th><th>Segment</th><th>Sensitivity</th><th>How</th><th>Hops</th></tr></thead>
              <tbody>
                {inc.reach.targets.slice(0, 15).map(t => (
                  <tr key={t.node}>
                    <td className="mono">{t.label}</td><td>{t.segment}</td>
                    <td><span className={`kc-sens ${t.sensitivity}`}>{t.sensitivity}</span></td>
                    <td>{t.basis.replace('_', ' ')}</td><td>{t.hops}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {inc.reach.targets.length > 15 && <div className="kc-muted">+ {inc.reach.targets.length - 15} more</div>}
        </section>

        <Review key={inc.incident_id} incidentId={inc.incident_id} initial={inc.review} />

        {inc.response?.length > 0 && (
          <section className="card kc-section">
            <h3>What to do</h3>
            {inc.response.slice(0, 12).map(a => (
              <div key={a.action_id} className="kc-md-li">• {a.title}. <span className="kc-muted">{a.why}</span></div>
            ))}
            {inc.response.length > 12 && <div className="kc-muted">+ {inc.response.length - 12} more</div>}
            <div className="kc-muted">Approve these on the Response Plan page.</div>
          </section>
        )}

        {inc.compliance?.length > 0 && (
          <section className="card kc-section">
            <h3>Controls affected</h3>
            <ControlTable controls={inc.compliance} />
          </section>
        )}

        {inc.actors?.length > 0 && (
          <section className="card kc-section">
            <h3>Linked actors</h3>
            <ActorTable actors={inc.actors} />
          </section>
        )}

        {inc.anomaly?.length > 0 && (
          <section className="card kc-section">
            <h3>Unusual behaviour</h3>
            <p className="kc-muted">Context only: anomaly scores do not change this incident's risk score.</p>
            <table className="kc-table static compact">
              <thead><tr><th>Entity</th><th>Anomaly score</th><th>Why</th></tr></thead>
              <tbody>
                {inc.anomaly.slice(0, 15).map(a => (
                  <tr key={`${a.kind}:${a.entity}`}>
                    <td className="mono">{a.entity}</td>
                    <td className="mono">{a.score.toFixed(1)}</td>
                    <td>{a.reasons.map(r => <div key={r}>{r}</div>)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        )}

        <section className="card kc-section">
          <div className="kc-section-head">
            <h3>Incident report</h3>
            <button className="btn-ghost" onClick={rewrite} disabled={aiBusy}>
              {aiBusy ? <Loader2 size={13} className="spin-slow" /> : <Sparkles size={13} />} Rewrite with AI
            </button>
          </div>
          {report && <Markdown text={report.body_markdown} />}
          {report && <div className="kc-muted">Generated by: {report.generated_by}</div>}
        </section>
      </div>
    </div>
  )
}
