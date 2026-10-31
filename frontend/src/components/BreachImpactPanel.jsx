import { useEffect, useRef, useState, useCallback } from 'react'
import { AlertTriangle, X } from 'lucide-react'
import { getBreachSimulation } from '../api'

// ── Constants ─────────────────────────────────────────────────────────────────

const SENSITIVITY_COLOR = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#94a3b8',
}

const IMPACT_STYLE = {
  CATASTROPHIC: 'border-rose-400/40 bg-rose-500/10 text-rose-300',
  SEVERE:       'border-orange-400/40 bg-orange-500/10 text-orange-300',
  MODERATE:     'border-yellow-400/40 bg-yellow-500/10 text-yellow-300',
  LOW:          'border-emerald-400/40 bg-emerald-500/10 text-emerald-300',
}

const IMPACT_GRADIENT = {
  CATASTROPHIC: 'from-rose-500 to-red-600',
  SEVERE:       'from-orange-400 to-amber-500',
  MODERATE:     'from-yellow-400 to-amber-400',
  LOW:          'from-emerald-400 to-teal-500',
}

// Legend filter definitions
const LEGEND_ITEMS = [
  { key: 'critical', label: 'Critical System',   dot: 'bg-rose-500' },
  { key: 'high',     label: 'High Sensitivity',  dot: 'bg-orange-500' },
  { key: 'lateral',  label: 'Lateral Reach',     dot: 'bg-indigo-500' },
  { key: 'user',     label: 'Compromised User',  dot: 'bg-slate-400' },
]

// ── Helpers ───────────────────────────────────────────────────────────────────

function trunc(label, n) {
  if (!label) return ''
  return label.length > n ? `${label.slice(0, n)}…` : label
}

function loadD3() {
  if (window.d3) return Promise.resolve(window.d3)
  return new Promise((resolve, reject) => {
    const existing = document.querySelector('script[data-d3="true"]')
    if (existing) {
      // Already loading — wait for it
      existing.addEventListener('load', () => resolve(window.d3))
      existing.addEventListener('error', reject)
      return
    }
    const script = document.createElement('script')
    script.src = 'https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js'
    script.async = true
    script.dataset.d3 = 'true'
    script.onload = () => resolve(window.d3)
    script.onerror = reject
    document.body.appendChild(script)
  })
}

// Build nodes + links from breach data
// Lateral nodes connect to direct nodes (distributed evenly), not to user center
function buildGraph(breachData, username) {
  const centerNode = {
    id: `user-${breachData.user_id}`,
    label: username || breachData.user_id,
    type: 'user',
    sensitivity: 'user',
    radius: 20,
    color: '#94a3b8',
  }

  const directNodes = (breachData.directly_accessible || []).map((item, i) => ({
    id: `direct-${item.system}-${i}`,
    label: item.system,
    type: 'direct',
    sensitivity: item.sensitivity,
    radius: 13,
    color: SENSITIVITY_COLOR[item.sensitivity] || SENSITIVITY_COLOR.low,
  }))

  const lateralNodes = (breachData.lateral_movement_risk || []).map((sys, i) => ({
    id: `lateral-${sys}-${i}`,
    label: sys,
    type: 'lateral',
    sensitivity: 'lateral',
    radius: 10,
    color: '#6366f1',
  }))

  const nodes = [centerNode, ...directNodes, ...lateralNodes]

  // Direct systems connect to user center (solid lines)
  const directLinks = directNodes.map(n => ({
    source: centerNode.id, target: n.id, kind: 'direct'
  }))

  // Lateral systems connect to a direct node parent (distributed evenly)
  // This creates a tree structure instead of hub-and-spoke
  const lateralLinks = lateralNodes.map((n, i) => {
    const parent = directNodes.length > 0
      ? directNodes[i % directNodes.length]
      : centerNode
    return { source: parent.id, target: n.id, kind: 'lateral' }
  })

  return { nodes, links: [...directLinks, ...lateralLinks] }
}

// ── BreachGraph component ─────────────────────────────────────────────────────

function BreachGraph({ breachData, username, height = 200, interactive = false, activeFilter, onFilterChange }) {
  const svgRef       = useRef(null)
  const containerRef = useRef(null)
  const simRef       = useRef(null)
  const nodesDataRef = useRef([]) // keep ref for filter effect

  // Tooltip state (interactive mode only)
  const [tooltip, setTooltip] = useState({ visible: false, x: 0, y: 0, node: null })

  // ── Build & render simulation ──────────────────────────────────────────────
  useEffect(() => {
    if (!breachData || !svgRef.current || !containerRef.current) return
    let cancelled = false

    const render = async () => {
      const d3 = await loadD3()
      if (cancelled || !svgRef.current || !containerRef.current) return

      const width  = containerRef.current.clientWidth || 500
      const { nodes, links } = buildGraph(breachData, username)
      nodesDataRef.current = nodes

      const svg = d3.select(svgRef.current)
      svg.selectAll('*').remove()
      svg
        .attr('viewBox', `0 0 ${width} ${height}`)
        .attr('preserveAspectRatio', 'xMidYMid meet')

      // ── Edges ──
      const linkG = svg.append('g').attr('class', 'links')
      const linkSel = linkG.selectAll('line')
        .data(links)
        .enter()
        .append('line')
        .attr('stroke', d => d.kind === 'lateral' ? '#4f46e5' : '#334155')
        .attr('stroke-opacity', 0.6)
        .attr('stroke-width', d => d.kind === 'direct' ? 1.8 : 1.2)
        .attr('stroke-dasharray', d => d.kind === 'lateral' ? '5,3' : '0')

      // ── Nodes ──
      const nodeG = svg.append('g').attr('class', 'nodes')
      const nodeSel = nodeG.selectAll('g')
        .data(nodes)
        .enter()
        .append('g')
        .attr('class', 'node-group')
        .style('cursor', interactive ? 'pointer' : 'default')

      // Circle
      nodeSel.append('circle')
        .attr('r', d => d.radius)
        .attr('fill', d => d.color)
        .attr('fill-opacity', d => d.type === 'user' ? 0.25 : 0.85)
        .attr('stroke', d => {
          if (d.type === 'user')    return '#94a3b8'
          if (d.type === 'lateral') return '#818cf8'
          return 'rgba(255,255,255,0.25)'
        })
        .attr('stroke-width', d => d.type === 'lateral' ? 1.5 : 1)
        .attr('stroke-dasharray', d => d.type === 'lateral' ? '3,2' : '0')

      // Label
      nodeSel.append('text')
        .attr('y', d => d.radius + (interactive ? 14 : 11))
        .attr('text-anchor', 'middle')
        .attr('font-size', interactive ? '10px' : '8px')
        .attr('fill', '#94a3b8')
        .attr('pointer-events', 'none')
        .text(d => interactive ? d.label : trunc(d.label, 8))

      // ── Tooltip events (interactive only) ──
      if (interactive) {
        nodeSel
          .on('mouseenter', (event, d) => {
            const rect = containerRef.current.getBoundingClientRect()
            setTooltip({
              visible: true,
              x: event.clientX - rect.left + 12,
              y: event.clientY - rect.top - 10,
              node: d,
            })
          })
          .on('mousemove', (event) => {
            const rect = containerRef.current.getBoundingClientRect()
            setTooltip(prev => ({
              ...prev,
              x: event.clientX - rect.left + 12,
              y: event.clientY - rect.top - 10,
            }))
          })
          .on('mouseleave', () => setTooltip({ visible: false, x: 0, y: 0, node: null }))
      }

      // ── Force simulation ──
      const sim = d3.forceSimulation(nodes)
        .force('link', d3.forceLink(links).id(d => d.id)
          .distance(d => d.kind === 'lateral' ? 70 : 100)
          .strength(0.6))
        .force('charge', d3.forceManyBody().strength(interactive ? -280 : -180))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(d => d.radius + (interactive ? 18 : 12)))

      sim.on('tick', () => {
        linkSel
          .attr('x1', d => d.source.x)
          .attr('y1', d => d.source.y)
          .attr('x2', d => d.target.x)
          .attr('y2', d => d.target.y)
        nodeSel.attr('transform', d => `translate(${d.x ?? 0},${d.y ?? 0})`)
      })

      simRef.current = sim
    }

    render()

    return () => {
      cancelled = true
      simRef.current?.stop()
      setTooltip({ visible: false, x: 0, y: 0, node: null })
    }
  }, [breachData, username, height, interactive])

  // ── Filter effect — runs independently when activeFilter changes ───────────
  useEffect(() => {
    if (!svgRef.current || !interactive) return
    const d3 = window.d3
    if (!d3) return

    const svg = d3.select(svgRef.current)

    const nodeMatch = d => {
      if (!activeFilter) return true
      if (activeFilter === 'critical') return d.sensitivity === 'critical'
      if (activeFilter === 'high')     return d.sensitivity === 'high'
      if (activeFilter === 'lateral')  return d.type === 'lateral'
      if (activeFilter === 'user')     return d.type === 'user'
      return true
    }

    // Update circles
    svg.selectAll('.node-group circle')
      .transition().duration(200)
      .attr('opacity', d => nodeMatch(d) ? 1 : 0.1)
      .attr('r', d => nodeMatch(d) && activeFilter ? d.radius + 3 : d.radius)

    // Update labels
    svg.selectAll('.node-group text')
      .transition().duration(200)
      .attr('opacity', d => nodeMatch(d) ? 1 : 0.08)
      .attr('fill', d => nodeMatch(d) && activeFilter ? '#e2e8f0' : '#94a3b8')
      .attr('font-size', d => nodeMatch(d) && activeFilter ? '11px' : '10px')

    // Update edges — dim if neither endpoint matches
    svg.selectAll('.links line')
      .transition().duration(200)
      .attr('stroke-opacity', d => {
        if (!activeFilter) return 0.6
        const srcMatch = nodeMatch(d.source)
        const tgtMatch = nodeMatch(d.target)
        return (srcMatch || tgtMatch) ? 0.6 : 0.04
      })
  }, [activeFilter, interactive])

  return (
    <div ref={containerRef} className="relative w-full">
      <svg ref={svgRef} style={{ height, width: '100%' }} />

      {/* Hover tooltip */}
      {interactive && tooltip.visible && tooltip.node && (
        <div
          className="pointer-events-none absolute z-10 rounded-xl border border-white/10 bg-slate-900/95 p-3 text-xs shadow-xl backdrop-blur"
          style={{ left: tooltip.x, top: tooltip.y, maxWidth: 180 }}
        >
          <div className="font-semibold text-white">{tooltip.node.label}</div>
          {tooltip.node.type !== 'user' && (
            <div className="mt-1 text-slate-400">
              Sensitivity: <span className="text-slate-200 capitalize">{tooltip.node.sensitivity}</span>
            </div>
          )}
          <div className="mt-0.5 text-slate-400">
            Type: <span className="text-slate-200">
              {tooltip.node.type === 'user'    ? 'Compromised User'  :
               tooltip.node.type === 'direct'  ? 'Direct Access'     :
               'Lateral Reach'}
            </span>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Interactive legend ────────────────────────────────────────────────────────

function GraphLegend({ activeFilter, onFilterChange }) {
  return (
    <div className="mt-3 flex flex-wrap gap-2">
      {LEGEND_ITEMS.map(item => {
        const isActive = activeFilter === item.key
        return (
          <button
            key={item.key}
            onClick={() => onFilterChange(isActive ? null : item.key)}
            className={`flex items-center gap-1.5 rounded-full border px-3 py-1 text-[10px] font-semibold uppercase tracking-widest transition ${
              isActive
                ? 'border-cyan-500/40 bg-cyan-500/10 text-cyan-300'
                : 'border-white/10 bg-white/5 text-slate-500 hover:border-white/20 hover:text-slate-300'
            }`}
          >
            <span className={`h-2 w-2 rounded-full ${item.dot}`} />
            {item.label}
          </button>
        )
      })}
    </div>
  )
}

// ── Full-screen modal ─────────────────────────────────────────────────────────

function GraphModal({ breachData, username, onClose }) {
  const [activeFilter, setActiveFilter] = useState(null)

  // Close on Escape key
  useEffect(() => {
    const handler = e => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [onClose])

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="relative flex w-[60vw] flex-col rounded-2xl border border-white/10 bg-slate-950 p-6 shadow-2xl"
        style={{ height: '70vh' }}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="mb-4 flex items-center justify-between">
          <div>
            <div className="text-[11px] uppercase tracking-widest text-slate-500">Lateral Movement Graph</div>
            <div className="mt-0.5 font-semibold text-white">{username}</div>
          </div>
          <button
            onClick={onClose}
            className="flex h-8 w-8 items-center justify-center rounded-xl border border-white/10 bg-white/5 text-slate-400 transition hover:bg-white/10 hover:text-white"
          >
            <X size={14} />
          </button>
        </div>

        {/* Graph fills remaining space */}
        <div className="min-h-0 flex-1 overflow-hidden rounded-xl border border-white/5 bg-black/30">
          <BreachGraph
            breachData={breachData}
            username={username}
            height={420}
            interactive={true}
            activeFilter={activeFilter}
            onFilterChange={setActiveFilter}
          />
        </div>

        {/* Interactive legend at bottom */}
        <GraphLegend activeFilter={activeFilter} onFilterChange={setActiveFilter} />

        <p className="mt-3 text-center text-[10px] text-slate-600">
          Click a legend item to highlight · Hover nodes for details · Press Esc to close
        </p>
      </div>
    </div>
  )
}

// ── Main panel ────────────────────────────────────────────────────────────────

export default function BreachImpactPanel({ user }) {
  const [breachData,  setBreachData]  = useState(null)
  const [loading,     setLoading]     = useState(false)
  const [error,       setError]       = useState('')
  const [showModal,   setShowModal]   = useState(false)

  useEffect(() => {
    let active = true

    if (!user) {
      setBreachData(null)
      setLoading(false)
      setError('')
      return
    }

    setLoading(true)
    setError('')
    setBreachData(null)

    getBreachSimulation(user.user_id)
      .then(data  => { if (active) setBreachData(data) })
      .catch(()   => { if (active) setError('Could not load breach simulation') })
      .finally(() => { if (active) setLoading(false) })

    return () => { active = false }
  }, [user?.user_id])

  if (!user) return null

  return (
    <>
      <section className="glass rounded-2xl border border-white/10 p-5 slide-up">
        {/* Section label */}
        <div className="flex items-center gap-2 text-[11px] uppercase tracking-widest text-slate-500">
          <AlertTriangle size={12} className="text-rose-400" /> Breach Impact
        </div>

        {/* Loading */}
        {loading && (
          <div className="mt-4 flex h-32 items-center justify-center text-sm text-slate-500">
            Simulating breach paths…
          </div>
        )}

        {/* Error */}
        {!loading && error && (
          <div className="mt-4 rounded-xl border border-rose-400/20 bg-rose-500/10 p-3 text-sm text-rose-300">
            {error}
          </div>
        )}

        {/* Content */}
        {!loading && !error && breachData && (
          <div className="mt-4 space-y-4">

            {/* Impact header row */}
            <div className="grid gap-3 sm:grid-cols-3">
              <div className="rounded-2xl border border-white/8 bg-white/4 p-4">
                <div className="text-[10px] uppercase tracking-widest text-slate-500">Estimated Impact</div>
                <div className="mt-2">
                  <span className={`chip border ${IMPACT_STYLE[breachData.estimated_impact] || IMPACT_STYLE.LOW}`}>
                    {breachData.estimated_impact}
                  </span>
                </div>
                <div className="mt-3 text-xs text-slate-400">
                  {breachData.pivot_user_count} users reachable
                </div>
              </div>

              <div className="rounded-2xl border border-white/8 bg-white/4 p-4 sm:col-span-2">
                <div className="flex items-center justify-between text-[10px] uppercase tracking-widest text-slate-500">
                  <span>Data Sensitivity Score</span>
                  <span className="text-slate-300">{Number(breachData.data_sensitivity_score).toFixed(1)} / 100</span>
                </div>
                <div className="mt-3 risk-bar">
                  <div
                    className={`risk-bar-fill bg-gradient-to-r ${IMPACT_GRADIENT[breachData.estimated_impact] || IMPACT_GRADIENT.LOW}`}
                    style={{ width: `${breachData.data_sensitivity_score}%` }}
                  />
                </div>
                <div className="mt-3 text-xs text-slate-400">
                  {breachData.lateral_movement_risk?.length || 0} systems in lateral reach
                </div>
              </div>
            </div>

            {/* Collapsed graph */}
            <div className="rounded-2xl border border-white/8 bg-black/30 p-3">
              <div className="text-[10px] uppercase tracking-widest text-slate-500 mb-2">
                Attack Path Preview
              </div>
              <BreachGraph
                breachData={breachData}
                username={user.username}
                height={200}
                interactive={false}
                activeFilter={null}
                onFilterChange={() => {}}
              />

              {/* Static mini legend (not interactive — save that for modal) */}
              <div className="mt-2 flex flex-wrap gap-3 text-[10px] text-slate-600">
                {LEGEND_ITEMS.map(item => (
                  <span key={item.key} className="flex items-center gap-1">
                    <span className={`h-1.5 w-1.5 rounded-full ${item.dot}`} />
                    {item.label}
                  </span>
                ))}
              </div>

              {/* Expand button */}
              <button
                onClick={() => setShowModal(true)}
                className="mt-3 w-full rounded-xl border border-white/10 bg-white/5 py-2 text-xs text-slate-400 transition hover:border-cyan-500/30 hover:bg-cyan-500/5 hover:text-cyan-300"
              >
                View Full Graph ↗
              </button>
            </div>

          </div>
        )}
      </section>

      {/* Full-screen modal */}
      {showModal && breachData && (
        <GraphModal
          breachData={breachData}
          username={user.username}
          onClose={() => setShowModal(false)}
        />
      )}
    </>
  )
}
