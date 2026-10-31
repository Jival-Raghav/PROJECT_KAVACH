import { useMemo, useState } from 'react'
import { Crosshair, MousePointerClick, Network, ShieldCheck } from 'lucide-react'
import IncidentGraph from './IncidentGraph'
import { BASIS, SENSITIVITY_LABEL, SENSITIVITY_ORDER } from './format'

const HUB = 'hub'
const SENS_TONE = { crown: 'bad', high: 'warn', medium: 'info', low: 'plain' }

function topSensitivity(targets) {
  return SENSITIVITY_ORDER.find(s => targets.some(t => t.sensitivity === s)) || targets[0]?.sensitivity
}

function groupTargets(targets) {
  const groups = new Map()
  targets.forEach(t => {
    const id = `group:${t.segment}|${t.basis}`
    if (!groups.has(id)) groups.set(id, { id, segment: t.segment, basis: t.basis, targets: [] })
    groups.get(id).targets.push(t)
  })
  const rank = g => SENSITIVITY_ORDER.indexOf(topSensitivity(g.targets))
  return [...groups.values()].sort((a, b) => rank(a) - rank(b) || b.targets.length - a.targets.length)
}

const isWholeSegment = g => g.targets.length === 1 && g.targets[0].node.startsWith('segment:')

function hubTitle(footholds) {
  if (footholds.length === 1) return footholds[0] === 'firewall' ? 'The firewall' : footholds[0]
  return `${footholds.length} compromised hosts`
}

/** A fixed, compact Hub → Segment summary. No inline expansion: a segment's own hosts are a
 * flat list of (mostly identical, high-count) nodes with nothing useful to show as a diagram,
 * so that detail lives in the side panel (filterable) instead of flooding the canvas. */
function buildGraph(reach, groups) {
  const nodes = [{
    id: HUB, col: 0, title: hubTitle(reach.footholds), sub: 'Attacker foothold', icon: Crosshair, tone: 'bad',
  }]
  const edges = []
  groups.forEach(g => {
    const sens = topSensitivity(g.targets)
    nodes.push({
      id: g.id, col: 1, title: g.segment, icon: Network, tone: SENS_TONE[sens] || 'plain',
      sub: isWholeSegment(g) ? `Whole segment · ${SENSITIVITY_LABEL[sens] || sens}`
        : `${g.targets.length} ${g.targets.length === 1 ? 'host' : 'hosts'} · ${SENSITIVITY_LABEL[sens] || sens}`,
    })
    const basis = BASIS[g.basis]
    edges.push({
      id: `edge:${g.id}`, source: HUB, target: g.id, tone: basis?.tone, dashed: !basis?.proven,
      pills: [{ text: basis?.label || g.basis, tone: basis?.tone }],
    })
  })
  return { nodes, edges }
}

const MAX_3D_PER_GROUP = 36

/** A dense hub → segment → target cloud for the 3D view. Reuses the 2D view's id scheme, so
 * clicking a node in either view resolves to the same panel. */
function build3DGraph(reach, groups) {
  const nodes = [{ id: HUB, col: 0, size: 9, title: hubTitle(reach.footholds), tone: 'bad' }]
  const edges = []
  groups.forEach(g => {
    const sens = topSensitivity(g.targets)
    const basis = BASIS[g.basis]
    nodes.push({ id: g.id, col: 1, size: 5, title: g.segment, tone: SENS_TONE[sens] || 'plain' })
    edges.push({ id: `edge:${g.id}`, source: HUB, target: g.id, tone: basis?.tone, dashed: !basis?.proven })
    const dense = g.targets.length > 8 // a handful stay lively; a whole segment just reads as a burst
    g.targets.slice(0, MAX_3D_PER_GROUP).forEach(t => {
      const id = `target:${g.id}|${t.node}`
      nodes.push({ id, col: 2, size: 2, title: t.label, tone: SENS_TONE[t.sensitivity] || 'plain', showLabel: false })
      edges.push({ id: `edge:${id}`, source: g.id, target: id, tone: basis?.tone, dashed: !basis?.proven, particles: !dense })
    })
    const more = g.targets.length - MAX_3D_PER_GROUP
    if (more > 0) {
      const id = `more:${g.id}`
      nodes.push({ id, col: 2, size: 2.6, title: `+${more}`, tone: 'plain' })
      edges.push({ id: `edge:${id}`, source: g.id, target: id, tone: basis?.tone, dashed: !basis?.proven })
    }
  })
  return { nodes, edges }
}

function TargetFacts({ target }) {
  const basis = BASIS[target.basis]
  return (
    <>
      <div className="kc-panel-kicker">Reachable target</div>
      <h3 className="kc-panel-title mono">{target.label}</h3>
      <div className="kc-kv"><span>Segment</span><b>{target.segment}</b></div>
      <div className="kc-kv"><span>Sensitivity</span><b><span className={`kc-sens ${target.sensitivity}`}>{SENSITIVITY_LABEL[target.sensitivity] || target.sensitivity}</span></b></div>
      <div className="kc-kv"><span>Distance</span><b>{target.hops} hop{target.hops === 1 ? '' : 's'}</b></div>
      <h4>{basis?.label || target.basis}</h4>
      <p>{basis?.help}</p>
    </>
  )
}

function GroupPanel({ group, onPick }) {
  const [filter, setFilter] = useState('')
  const basis = BASIS[group.basis]
  const q = filter.trim().toLowerCase()
  const rows = q ? group.targets.filter(t => t.label.toLowerCase().includes(q)) : group.targets
  return (
    <>
      <div className="kc-panel-kicker">Network segment</div>
      <h3 className="kc-panel-title">{group.segment}</h3>
      <div className="kc-kv"><span>How it is reached</span><b>{basis?.label || group.basis}</b></div>
      <div className="kc-kv"><span>Highest sensitivity</span><b>{SENSITIVITY_LABEL[topSensitivity(group.targets)]}</b></div>
      <p>{basis?.help}</p>
      {isWholeSegment(group) ? <p className="mono">{group.targets[0].label}</p> : (
        <>
          <h4>All {group.targets.length} targets</h4>
          <input className="kc-filter" value={filter} onChange={e => setFilter(e.target.value)}
            placeholder="Filter by IP" aria-label="Filter targets by IP" />
          <div className="kc-target-list">
            {rows.map(t => (
              <button key={t.node} onClick={() => onPick(t)}>
                <span className="mono">{t.label}</span>
                <span className={`kc-sens ${t.sensitivity}`}>{SENSITIVITY_LABEL[t.sensitivity] || t.sensitivity}</span>
              </button>
            ))}
            {rows.length === 0 && <div className="kc-muted">No target matches.</div>}
          </div>
        </>
      )}
    </>
  )
}

function HubPanel({ reach }) {
  return (
    <>
      <div className="kc-panel-kicker">Attacker foothold</div>
      <h3 className="kc-panel-title">{hubTitle(reach.footholds)}</h3>
      <p>Where the attacker already has a position. Everything on this page is measured from here.</p>
      <h4>Footholds ({reach.footholds.length})</h4>
      <div className="kc-target-list plain">
        {reach.footholds.map(f => <div key={f} className="mono">{f}</div>)}
      </div>
    </>
  )
}

export default function BlastRadiusTab({ inc }) {
  const { reach } = inc
  const groups = useMemo(() => groupTargets(reach.targets), [reach.targets])
  const [selected, setSelected] = useState(null)
  const [pickedTarget, setPickedTarget] = useState(null)
  const graph = useMemo(() => buildGraph(reach, groups), [reach, groups])
  const graph3d = useMemo(() => build3DGraph(reach, groups), [reach, groups])

  const select = id => {
    setSelected(id)
    setPickedTarget(null)
  }

  const seen = reach.targets.filter(t => t.basis === 'observed').length
  const top = topSensitivity(reach.targets)
  const edgeGroup = selected?.startsWith('edge:') ? groups.find(g => `edge:${g.id}` === selected) : null
  const group = groups.find(g => g.id === selected) || edgeGroup
    || (selected?.startsWith('more:') ? groups.find(g => `more:${g.id}` === selected) : null)
  const target = pickedTarget || (selected?.startsWith('target:')
    ? reach.targets.find(t => selected.endsWith(`|${t.node}`)) : null)

  return (
    <div className="kc-tab-page">
      <div className="kc-tab-intro">
        <h3>Blast radius (What if?)</h3>
        <p><b>What if this attacker is not stopped?</b> {reach.summary}</p>
      </div>

      {reach.targets.length === 0 ? (
        <div className="card kc-empty-state">
          <ShieldCheck size={28} />
          <b>No onward reach found</b>
          <span>Kavach found no foothold or reachable target for this incident.</span>
        </div>
      ) : (
        <>
          <div className="kc-stat-row">
            <div className="kc-stat"><b>{reach.targets.length.toLocaleString()}</b><span>Targets in range</span></div>
            <div className="kc-stat"><b>{seen.toLocaleString()}</b><span>Backed by observed traffic</span></div>
            <div className="kc-stat"><b>{(reach.targets.length - seen).toLocaleString()}</b><span>Possible, not observed</span></div>
            <div className="kc-stat"><b>{SENSITIVITY_LABEL[top] || top}</b><span>Most sensitive target</span></div>
          </div>
          <div className="kc-split">
            <IncidentGraph nodes={graph.nodes} edges={graph.edges}
              nodes3d={graph3d.nodes} edges3d={graph3d.edges} physics
              selected={selected} onSelect={select}
              ariaLabel={`Blast radius for incident ${inc.incident_id}`} />
            <aside className="card kc-panel">
              {target ? <TargetFacts target={target} />
                : group ? <GroupPanel key={group.id} group={group} onPick={setPickedTarget} />
                  : selected === HUB ? <HubPanel reach={reach} />
                    : (
                      <div className="kc-panel-empty">
                        <MousePointerClick size={20} />
                        <b>Click a segment</b>
                        <span>Its hosts, filterable, are listed here.</span>
                      </div>
                    )}
            </aside>
          </div>
          <div className="kc-key">
            <span><i className="kc-key-line" />Solid line: {seen ? 'seen in the log or firewall control' : 'firewall control'}</span>
            <span><i className="kc-key-line dashed" />Dashed line: possible, not observed</span>
            <span className="kc-key-sep" />
            {SENSITIVITY_ORDER.map(s => (
              <span key={s}><i className={`kc-key-box tone-${SENS_TONE[s]}`} />{SENSITIVITY_LABEL[s]}</span>
            ))}
          </div>
        </>
      )}
    </div>
  )
}
