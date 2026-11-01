import { useCallback, useEffect, useMemo, useRef } from 'react'
import * as d3 from 'd3'
import { Maximize, Minus, Plus } from 'lucide-react'

const NODE_W = 196
const NODE_H = 60
const ROW_GAP = 16
const SUB_GAP = 20
const MAX_ROWS = 12
const GAP_PLAIN = 120
const GAP_LABELLED = 280
const PILL_W = 232
const PILL_H = 22
const PILL_GAP = 4

const clip = (text, n) => (text.length > n ? `${text.slice(0, n - 1)}…` : text)

/** Places nodes left to right by `col`. A very tall column wraps into several sub-columns. */
export function layoutGraph(nodes, edges) {
  const byCol = d3.group(nodes, n => n.col)
  const cols = [...byCol.keys()].sort((a, b) => a - b)
  const colOf = new Map(nodes.map(n => [n.id, n.col]))
  const labelledAfter = new Set()
  edges.forEach(e => {
    if (e.pills?.length) labelledAfter.add(Math.min(colOf.get(e.source), colOf.get(e.target)))
  })
  const tallest = Math.max(1, ...cols.map(c => Math.min(byCol.get(c).length, MAX_ROWS)))
  const fullHeight = tallest * NODE_H + (tallest - 1) * ROW_GAP
  const pos = new Map()
  let x = 0
  cols.forEach(c => {
    const list = byCol.get(c)
    const subCols = Math.ceil(list.length / MAX_ROWS)
    const rows = Math.min(list.length, MAX_ROWS)
    const top = (fullHeight - (rows * NODE_H + (rows - 1) * ROW_GAP)) / 2
    list.forEach((n, i) => {
      const sub = Math.floor(i / MAX_ROWS)
      const row = i % MAX_ROWS
      pos.set(n.id, { x: x + sub * (NODE_W + SUB_GAP), y: top + row * (NODE_H + ROW_GAP) })
    })
    x += subCols * NODE_W + (subCols - 1) * SUB_GAP + (labelledAfter.has(c) ? GAP_LABELLED : GAP_PLAIN)
  })
  return pos
}

function edgeGeometry(a, b, colSpan) {
  const forward = b.x >= a.x
  const x1 = forward ? a.x + NODE_W : a.x
  const x2 = forward ? b.x : b.x + NODE_W
  const y1 = a.y + NODE_H / 2
  const y2 = b.y + NODE_H / 2
  // A link that skips a column arcs over it; a backward link arcs under, so neither crosses a node.
  const arc = !forward ? -130 : colSpan > 1 ? 40 + 90 * colSpan : 0
  const dx = (forward ? 1 : -1) * Math.max(50, Math.abs(x2 - x1) / 2)
  return {
    d: `M${x1},${y1} C${x1 + dx},${y1 - arc} ${x2 - dx},${y2 - arc} ${x2},${y2}`,
    mx: (x1 + x2) / 2,
    my: (y1 + y2) / 2 - 0.75 * arc,
  }
}

/**
 * Pan-and-zoom graph. nodes: {id, col, title, sub, tone, icon, tag}.
 * edges: {id, source, target, tone, dashed, pills: [{no, text, tone}]}. Selection is owned by the caller.
 */
export default function GraphCanvas({ nodes, edges, selected, onSelect, ariaLabel }) {
  const svgRef = useRef(null)
  const groupRef = useRef(null)
  const zoomRef = useRef(null)
  const pos = useMemo(() => layoutGraph(nodes, edges), [nodes, edges])
  const colOf = useMemo(() => new Map(nodes.map(n => [n.id, n.col])), [nodes])

  const fit = useCallback(() => {
    const svg = svgRef.current
    const group = groupRef.current
    if (!svg || !group || !zoomRef.current) return
    const box = group.getBBox()
    const { clientWidth: w, clientHeight: h } = svg
    if (!box.width || !w || !h) return
    const k = Math.min(1.2, 0.92 * Math.min(w / box.width, h / box.height))
    const t = d3.zoomIdentity
      .translate((w - box.width * k) / 2 - box.x * k, (h - box.height * k) / 2 - box.y * k).scale(k)
    d3.select(svg).call(zoomRef.current.transform, t)
  }, [])

  useEffect(() => {
    const zoom = d3.zoom().scaleExtent([0.15, 3])
      .on('zoom', ev => d3.select(groupRef.current).attr('transform', ev.transform))
    zoomRef.current = zoom
    const svg = d3.select(svgRef.current).call(zoom).on('dblclick.zoom', null)
    return () => { svg.on('.zoom', null) }
  }, [])

  useEffect(fit, [fit, nodes, edges])

  const scaleBy = k => d3.select(svgRef.current).call(zoomRef.current.scaleBy, k)
  const activeEdges = useMemo(() => {
    if (!selected) return null
    return new Set(edges.filter(e => e.id === selected || e.source === selected || e.target === selected)
      .map(e => e.id))
  }, [selected, edges])
  const pick = (ev, id) => { ev.stopPropagation(); onSelect(id) }
  const onKey = (ev, id) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); onSelect(id) } }

  return (
    <div className="kc-canvas">
      <div className="kc-canvas-tools">
        <button onClick={() => scaleBy(1.3)} title="Zoom in" aria-label="Zoom in"><Plus size={14} /></button>
        <button onClick={() => scaleBy(0.77)} title="Zoom out" aria-label="Zoom out"><Minus size={14} /></button>
        <button onClick={fit} title="Fit to view" aria-label="Fit to view"><Maximize size={14} /></button>
      </div>
      <svg ref={svgRef} className="kc-canvas-svg" role="img" aria-label={ariaLabel} onClick={() => onSelect(null)}>
        <defs>
          <marker id="kc-arrow" viewBox="0 -5 10 10" refX="9" markerWidth="7" markerHeight="7" orient="auto">
            <path d="M0,-5L10,0L0,5" fill="var(--text-muted)" />
          </marker>
        </defs>
        <g ref={groupRef}>
          {edges.map(e => {
            const a = pos.get(e.source)
            const b = pos.get(e.target)
            if (!a || !b) return null
            const geo = edgeGeometry(a, b, colOf.get(e.target) - colOf.get(e.source))
            const dim = activeEdges && !activeEdges.has(e.id)
            const pills = e.pills || []
            const stack = pills.length * PILL_H + (pills.length - 1) * PILL_GAP
            return (
              <g key={e.id} className={`kc-edge tone-${e.tone || 'plain'}${dim ? ' dim' : ''}${selected === e.id ? ' on' : ''}`}
                onClick={ev => pick(ev, e.id)}>
                <path className="kc-edge-hit" d={geo.d} />
                <path className={`kc-edge-line${e.dashed ? ' dashed' : ''}`} d={geo.d} markerEnd="url(#kc-arrow)" />
                {pills.map((p, i) => {
                  const y = geo.my - stack / 2 + i * (PILL_H + PILL_GAP)
                  return (
                    <g key={`${p.no ?? ''}${p.text}`} className={`kc-pill tone-${p.tone || 'plain'}`}
                      transform={`translate(${geo.mx - PILL_W / 2},${y})`} tabIndex={0} role="button"
                      aria-label={p.text} onKeyDown={ev => onKey(ev, e.id)}>
                      <title>{p.text}</title>
                      <rect width={PILL_W} height={PILL_H} rx={PILL_H / 2} />
                      {p.no != null && (
                        <>
                          <circle className="kc-pill-no" cx={11} cy={11} r={8} />
                          <text className="kc-pill-no-text" x={11} y={15} textAnchor="middle">{p.no}</text>
                        </>
                      )}
                      <text x={p.no != null ? 24 : 12} y={15}>{clip(p.text, p.no != null ? 35 : 38)}</text>
                    </g>
                  )
                })}
              </g>
            )
          })}
          {nodes.map(n => {
            const { x, y } = pos.get(n.id)
            const Icon = n.icon
            const dim = selected && selected !== n.id && activeEdges
              && ![...activeEdges].some(id => {
                const e = edges.find(ed => ed.id === id)
                return e && (e.source === n.id || e.target === n.id)
              })
            return (
              <g key={n.id} transform={`translate(${x},${y})`}
                className={`kc-node tone-${n.tone || 'plain'}${selected === n.id ? ' on' : ''}${dim ? ' dim' : ''}`}
                onClick={ev => pick(ev, n.id)} onKeyDown={ev => onKey(ev, n.id)}
                tabIndex={0} role="button" aria-label={`${n.title}, ${n.sub}`}>
                <title>{`${n.title}\n${n.sub}`}</title>
                <rect className="kc-node-box" width={NODE_W} height={NODE_H} rx={10} />
                <rect className="kc-node-stripe" width={5} height={NODE_H - 16} x={0} y={8} rx={2.5} />
                {Icon && <Icon x={15} y={20} width={20} height={20} className="kc-node-icon" />}
                <text className="kc-node-title" x={44} y={26}>{clip(n.title, 21)}</text>
                <text className="kc-node-sub" x={44} y={44}>{clip(n.sub, 25)}</text>
                {n.tag && <text className="kc-node-tag" x={NODE_W - 10} y={17} textAnchor="end">{n.tag}</text>}
              </g>
            )
          })}
        </g>
      </svg>
      <div className="kc-canvas-hint">Drag to move · scroll to zoom · drag the bottom-right corner to resize</div>
    </div>
  )
}
