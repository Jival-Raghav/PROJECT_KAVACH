import { useMemo, useState } from 'react'
import { Globe, MousePointerClick, Server, ShieldHalf, User } from 'lucide-react'
import IncidentGraph from './IncidentGraph'
import { KIND, OUTCOME, fmtTime, prettifyText } from './format'

const NODE_LOOK = {
  external_ip: { icon: Globe, tone: 'bad' },
  host: { icon: Server, tone: 'info' },
  user: { icon: User, tone: 'warn' },
  firewall: { icon: ShieldHalf, tone: 'purple' },
  domain: { icon: Globe, tone: 'plain' },
}
const MAX_LABELLED_LINKS = 8

/** Column = longest chain of steps leading to the node, ignoring links that would form a loop. */
function columns(nodes, edges) {
  const out = new Map(nodes.map(n => [n.id, []]))
  const incoming = new Map(nodes.map(n => [n.id, 0]))
  edges.forEach(e => {
    out.get(e.source)?.push(e.target)
    if (incoming.has(e.target)) incoming.set(e.target, incoming.get(e.target) + 1)
  })
  const roots = nodes.filter(n => !incoming.get(n.id)).map(n => n.id)
  const col = new Map()
  const visiting = new Set()
  const visit = (id, depth) => {
    if (visiting.has(id) || (col.get(id) ?? -1) >= depth) return
    col.set(id, depth)
    visiting.add(id)
    out.get(id)?.forEach(t => visit(t, depth + 1))
    visiting.delete(id)
  }
  roots.forEach(r => visit(r, 0))
  nodes.forEach(n => { if (!col.has(n.id)) visit(n.id, 0) })
  return col
}

function buildGraph(inc) {
  const { nodes, edges } = inc.path
  const stepOf = new Map(inc.timeline.map((s, i) => [`${s.technique_id}|${s.ts}`, { ...s, no: i + 1 }]))
  const pairs = new Map()
  edges.forEach(e => {
    const key = `${e.source}|${e.target}`
    if (!pairs.has(key)) pairs.set(key, { id: key, source: e.source, target: e.target, steps: [] })
    const step = stepOf.get(`${e.technique_id}|${e.ts}`)
      || { no: null, technique_id: e.technique_id, technique_name: e.label, ts: e.ts }
    const list = pairs.get(key).steps
    if (!list.some(s => s.technique_id === step.technique_id && s.ts === step.ts)) list.push(step)
  })
  const links = [...pairs.values()]
  const labelled = links.length <= MAX_LABELLED_LINKS
  const col = columns(nodes, edges)
  return {
    labelled,
    links,
    gNodes: nodes.map(n => ({
      id: n.id,
      col: col.get(n.id) ?? 0,
      title: n.label,
      sub: n.segment || KIND[n.kind]?.label || n.kind,
      ...(NODE_LOOK[n.kind] || { tone: 'plain' }),
    })),
    gEdges: links.map(l => ({
      id: l.id,
      source: l.source,
      target: l.target,
      pills: labelled ? l.steps.map(s => ({
        no: s.no, text: s.technique_name, tone: OUTCOME[s.outcome]?.tone,
      })) : [],
    })),
  }
}

function StepCard({ step }) {
  const outcome = OUTCOME[step.outcome]
  return (
    <div className="kc-mini-step">
      <div className="kc-mini-step-head">
        {step.no != null && <span className="kc-step-no">{step.no}</span>}
        <b>{step.technique_name}</b>
      </div>
      <div className="kc-muted">{fmtTime(step.ts)}</div>
      <div className="kc-mini-step-tags">
        <span className="chip kc-chip mono">{step.technique_id}</span>
        {outcome && <span className={`kc-outcome tone-${outcome.tone}`}>{outcome.label}</span>}
      </div>
      {step.description && <p>{prettifyText(step.description)}</p>}
    </div>
  )
}

function NodePanel({ node, links, inc }) {
  const related = links.filter(l => l.source === node.id || l.target === node.id)
  const steps = [...new Map(related.flatMap(l => l.steps).map(s => [`${s.technique_id}|${s.ts}`, s])).values()]
    .sort((a, b) => (a.no ?? 0) - (b.no ?? 0))
  const anomaly = inc.anomaly?.find(a => a.entity === node.label)
  const actions = inc.response?.filter(a => a.target === node.label) || []
  return (
    <>
      <div className="kc-panel-kicker">{KIND[node.kind]?.label || node.kind}</div>
      <h3 className="kc-panel-title mono">{node.label}</h3>
      <p>{KIND[node.kind]?.help}</p>
      {node.segment && <div className="kc-kv"><span>Network segment</span><b className="mono">{node.segment}</b></div>}
      <h4>Steps involving it ({steps.length})</h4>
      {steps.map(s => <StepCard key={`${s.technique_id}|${s.ts}`} step={s} />)}
      {anomaly && (
        <>
          <h4>Unusual behaviour (score {anomaly.score.toFixed(1)})</h4>
          <ul className="kc-list">{anomaly.reasons.map(r => <li key={r}>{r}</li>)}</ul>
        </>
      )}
      {actions.length > 0 && (
        <>
          <h4>Proposed response</h4>
          <ul className="kc-list">{actions.map(a => <li key={a.action_id}>{a.title}</li>)}</ul>
        </>
      )}
    </>
  )
}

function LinkPanel({ link, nodes }) {
  const name = id => nodes.find(n => n.id === id)?.label || id
  return (
    <>
      <div className="kc-panel-kicker">Link</div>
      <h3 className="kc-panel-title"><span className="mono">{name(link.source)}</span> → <span className="mono">{name(link.target)}</span></h3>
      <p>{link.steps.length === 1 ? 'One attack step involved both of these.' : `${link.steps.length} attack steps involved both of these.`}</p>
      {link.steps.map(s => <StepCard key={`${s.technique_id}|${s.ts}`} step={s} />)}
    </>
  )
}

export default function AttackPathTab({ inc }) {
  const [selected, setSelected] = useState(null)
  const { labelled, links, gNodes, gEdges } = useMemo(() => buildGraph(inc), [inc])
  const node = inc.path.nodes.find(n => n.id === selected)
  const link = links.find(l => l.id === selected)
  const kinds = [...new Set(inc.path.nodes.map(n => n.kind))]

  return (
    <div className="kc-tab-page">
      <div className="kc-tab-intro">
        <h3>Attack path</h3>
        <p>
          Each box is something that took part in this incident. Each line means one or more attack
          steps involved both ends. Read left to right; the numbers give the order the steps happened.
          Lines show what was involved, not which way data moved.
          {!labelled && ` This incident has ${links.length} links, so click one to see its steps.`}
        </p>
      </div>
      <div className="kc-split">
        <IncidentGraph nodes={gNodes} edges={gEdges} selected={selected} onSelect={setSelected}
          ariaLabel={`Attack path for incident ${inc.incident_id}`} />
        <aside className="card kc-panel">
          {node ? <NodePanel node={node} links={links} inc={inc} />
            : link ? <LinkPanel link={link} nodes={inc.path.nodes} />
              : (
                <div className="kc-panel-empty">
                  <MousePointerClick size={20} />
                  <b>Click a box or line</b>
                  <span>Its details and the steps behind it appear here.</span>
                </div>
              )}
        </aside>
      </div>
      <div className="kc-key">
        {kinds.map(k => (
          <span key={k}><i className={`kc-key-box tone-${NODE_LOOK[k]?.tone || 'plain'}`} />{KIND[k]?.label || k}</span>
        ))}
        <span className="kc-key-sep" />
        {Object.values(OUTCOME).map(o => (
          <span key={o.label} title={o.help}><i className={`kc-key-dot tone-${o.tone}`} />{o.label}</span>
        ))}
      </div>
    </div>
  )
}
