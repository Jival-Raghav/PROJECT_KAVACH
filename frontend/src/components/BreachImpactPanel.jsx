import { useEffect, useRef, useState, useCallback } from 'react'
import { createPortal } from 'react-dom'
import { AlertTriangle, X } from 'lucide-react'
import { getBreachSimulation } from '../api'

// ── Constants ─────────────────────────────────────────────────────────────────

const SENSITIVITY_COLOR = {
  critical: '#E3000B',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#94a3b8',
}

// Glow colour per node type (for SVG filter / stroke)
const NODE_GLOW = {
  critical: '#E3000B',
  high:     '#f97316',
  medium:   '#eab308',
  lateral:  '#818cf8',
  user:     '#60a5fa',
  low:      '#94a3b8',
}

const IMPACT_BADGE_CLS = {
  CATASTROPHIC: 'badge-critical',
  SEVERE:       'badge-review',
  MODERATE:     'badge-review',
  LOW:          'badge-normal',
}

const IMPACT_BAR_COLOR = {
  CATASTROPHIC: 'var(--c-critical)',
  SEVERE:       'var(--c-review)',
  MODERATE:     'var(--c-review)',
  LOW:          'var(--c-normal)',
}

// Legend filter definitions
const LEGEND_ITEMS = [
  { key: 'critical', label: 'Critical System',   color: '#E3000B'  },
  { key: 'high',     label: 'High Sensitivity',  color: '#f97316'  },
  { key: 'lateral',  label: 'Lateral Reach',     color: '#818cf8'  },
  { key: 'user',     label: 'Compromised User',  color: '#60a5fa'  },
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
// height prop is kept only for the non-interactive mini-preview.
// In interactive/modal mode the component fills its container via ResizeObserver.

function BreachGraph({ breachData, username, height = 200, interactive = false, activeFilter, onFilterChange }) {
  const svgRef       = useRef(null)
  const containerRef = useRef(null)
  const simRef       = useRef(null)
  const nodesDataRef = useRef([])

  // Actual rendered dimensions (updated by ResizeObserver in interactive mode)
  const [dims, setDims] = useState({ w: 0, h: 0 })

  // Tooltip state (interactive mode only)
  const [tooltip, setTooltip] = useState({ visible: false, x: 0, y: 0, node: null })

  // ── ResizeObserver: measure container in interactive mode ──────────────────
  useEffect(() => {
    if (!interactive || !containerRef.current) return
    const obs = new ResizeObserver(entries => {
      for (const entry of entries) {
        const { width, height: h } = entry.contentRect
        if (width > 0 && h > 0) setDims({ w: Math.floor(width), h: Math.floor(h) })
      }
    })
    obs.observe(containerRef.current)
    // Initial measure
    const r = containerRef.current.getBoundingClientRect()
    if (r.width > 0 && r.height > 0) setDims({ w: Math.floor(r.width), h: Math.floor(r.height) })
    return () => obs.disconnect()
  }, [interactive])

  // ── Build & render simulation ──────────────────────────────────────────────
  useEffect(() => {
    if (!breachData || !svgRef.current || !containerRef.current) return

    // In interactive mode, wait until ResizeObserver gives us real dimensions
    const width  = interactive ? (dims.w || containerRef.current.clientWidth || 600) : (containerRef.current.clientWidth || 320)
    const h      = interactive ? (dims.h || containerRef.current.clientHeight || 400) : height
    if (interactive && (width < 10 || h < 10)) return  // not mounted yet

    let cancelled = false

    const render = async () => {
      const d3 = await loadD3()
      if (cancelled || !svgRef.current || !containerRef.current) return

      const { nodes, links } = buildGraph(breachData, username)
      nodesDataRef.current = nodes

      const svg = d3.select(svgRef.current)
      svg.selectAll('*').remove()
      svg
        .attr('viewBox', `0 0 ${width} ${h}`)
        .attr('width',  width)
        .attr('height', h)
        .attr('preserveAspectRatio', 'xMidYMid meet')
        .style('background', 'transparent')

      // ── SVG Defs: glow filters ──
      const defs = svg.append('defs')
      Object.entries(NODE_GLOW).forEach(([key, colour]) => {
        const f = defs.append('filter').attr('id', `glow-${key}`).attr('x', '-50%').attr('y', '-50%').attr('width', '200%').attr('height', '200%')
        f.append('feGaussianBlur').attr('stdDeviation', interactive ? '3' : '2').attr('result', 'blur')
        const merge = f.append('feMerge')
        merge.append('feMergeNode').attr('in', 'blur')
        merge.append('feMergeNode').attr('in', 'SourceGraphic')
      })

      // ── Edges ──
      const linkG = svg.append('g').attr('class', 'links')
      const linkSel = linkG.selectAll('line')
        .data(links)
        .enter()
        .append('line')
        .attr('stroke', d => d.kind === 'lateral' ? '#818cf8' : '#475569')
        .attr('stroke-opacity', d => d.kind === 'lateral' ? 0.5 : 0.7)
        .attr('stroke-width', d => d.kind === 'direct' ? 1.5 : 1)
        .attr('stroke-dasharray', d => d.kind === 'lateral' ? '5,4' : '0')
        .attr('filter', d => d.kind === 'lateral' ? 'url(#glow-lateral)' : 'none')

      // ── Nodes ──
      const nodeG = svg.append('g').attr('class', 'nodes')
      const nodeSel = nodeG.selectAll('g')
        .data(nodes)
        .enter()
        .append('g')
        .attr('class', 'node-group')
        .style('cursor', interactive ? 'pointer' : 'default')

      // Outer ring (halo) for user node
      nodeSel.filter(d => d.type === 'user')
        .append('circle')
        .attr('r', d => d.radius + 7)
        .attr('fill', 'none')
        .attr('stroke', '#60a5fa')
        .attr('stroke-width', 0.8)
        .attr('stroke-opacity', 0.35)
        .attr('stroke-dasharray', '3,4')

      // Main circle
      nodeSel.append('circle')
        .attr('r', d => d.radius)
        .attr('fill', d => d.type === 'user' ? '#0a1628' : d.color)
        .attr('fill-opacity', d => d.type === 'user' ? 0.9 : 0.80)
        .attr('stroke', d => NODE_GLOW[d.sensitivity] || NODE_GLOW[d.type] || '#475569')
        .attr('stroke-width', d => d.type === 'user' ? 1.5 : d.type === 'lateral' ? 1.2 : 1.5)
        .attr('stroke-dasharray', d => d.type === 'lateral' ? '4,3' : '0')
        .attr('stroke-opacity', 0.9)
        .attr('filter', d => {
          const key = d.sensitivity === 'critical' ? 'critical'
                    : d.sensitivity === 'high'     ? 'high'
                    : d.type === 'lateral'          ? 'lateral'
                    : d.type === 'user'             ? 'user'
                    : 'low'
          return `url(#glow-${key})`
        })

      // Label
      nodeSel.append('text')
        .attr('y', d => d.radius + (interactive ? 15 : 12))
        .attr('text-anchor', 'middle')
        .attr('font-size', interactive ? '10px' : '8px')
        .attr('font-family', 'Inter, system-ui, sans-serif')
        .attr('font-weight', '500')
        .attr('letter-spacing', '0.02em')
        .attr('fill', d => {
          if (d.type === 'user')              return '#93c5fd'
          if (d.type === 'lateral')           return '#a5b4fc'
          if (d.sensitivity === 'critical')   return '#fca5a5'
          if (d.sensitivity === 'high')       return '#fdba74'
          return '#94a3b8'
        })
        .attr('pointer-events', 'none')
        .text(d => interactive ? d.label : trunc(d.label, 8))

      // ── Tooltip events (interactive only) ──
      if (interactive) {
        nodeSel
          .on('mouseenter', (event, d) => {
            const rect = containerRef.current.getBoundingClientRect()
            setTooltip({ visible: true, x: event.clientX - rect.left + 12, y: event.clientY - rect.top - 10, node: d })
          })
          .on('mousemove', (event) => {
            const rect = containerRef.current.getBoundingClientRect()
            setTooltip(prev => ({ ...prev, x: event.clientX - rect.left + 12, y: event.clientY - rect.top - 10 }))
          })
          .on('mouseleave', () => setTooltip({ visible: false, x: 0, y: 0, node: null }))
      }

      // ── Force simulation ──
      const sim = d3.forceSimulation(nodes)
        .force('link', d3.forceLink(links).id(d => d.id)
          .distance(d => d.kind === 'lateral' ? (interactive ? 90 : 70) : (interactive ? 130 : 100))
          .strength(0.6))
        .force('charge', d3.forceManyBody().strength(interactive ? -320 : -180))
        .force('center', d3.forceCenter(width / 2, h / 2))
        .force('collision', d3.forceCollide().radius(d => d.radius + (interactive ? 20 : 12)))
        // Clamp nodes inside the SVG so nothing is cut off
        .force('bound', () => {
          const pad = 40
          nodes.forEach(n => {
            n.x = Math.max(pad, Math.min(width - pad, n.x ?? width / 2))
            n.y = Math.max(pad, Math.min(h    - pad, n.y ?? h    / 2))
          })
        })

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
  // dims triggers re-render when ResizeObserver fires in interactive mode
  }, [breachData, username, height, interactive, dims])

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
    <div
      ref={containerRef}
      style={{
        position: 'relative', width: '100%',
        // In interactive mode, fill 100% of parent height
        height: interactive ? '100%' : height,
        overflow: 'hidden',
      }}
    >
      <svg
        ref={svgRef}
        style={{
          width: '100%',
          height: interactive ? '100%' : height,
          display: 'block',
        }}
      />

      {/* Hover tooltip */}
      {interactive && tooltip.visible && tooltip.node && (
        <div
          style={{
            position: 'absolute', left: tooltip.x, top: tooltip.y,
            maxWidth: 180, pointerEvents: 'none', zIndex: 20,
            background: 'rgba(10,18,40,0.97)',
            border: '1px solid rgba(96,165,250,0.25)',
            borderRadius: 6, padding: '8px 12px',
            backdropFilter: 'blur(12px)',
            boxShadow: '0 0 18px rgba(96,165,250,0.12), 0 4px 20px rgba(0,0,0,0.5)',
          }}
        >
          <div style={{ fontWeight: 600, fontSize: 12, color: '#e2e8f0', marginBottom: 4 }}>{tooltip.node.label}</div>
          {tooltip.node.type !== 'user' && (
            <div style={{ fontSize: 11, color: '#64748b' }}>
              Sensitivity: <span style={{ color: '#cbd5e1', textTransform: 'capitalize' }}>{tooltip.node.sensitivity}</span>
            </div>
          )}
          <div style={{ fontSize: 11, color: '#64748b', marginTop: 2 }}>
            Type: <span style={{ color: '#cbd5e1' }}>
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
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 14 }}>
      {LEGEND_ITEMS.map(item => {
        const isActive = activeFilter === item.key
        return (
          <button
            key={item.key}
            onClick={() => onFilterChange(isActive ? null : item.key)}
            style={{
              display: 'flex', alignItems: 'center', gap: 7,
              padding: '5px 14px', borderRadius: 9999,
              border: `1px solid ${isActive ? item.color : 'rgba(255,255,255,0.10)'}`,
              background: isActive ? `${item.color}18` : 'rgba(255,255,255,0.03)',
              color: isActive ? item.color : '#64748b',
              fontSize: 10, fontWeight: 600, textTransform: 'uppercase',
              letterSpacing: '0.08em', cursor: 'pointer',
              transition: 'all 150ms ease',
              boxShadow: isActive ? `0 0 10px ${item.color}33` : 'none',
            }}
          >
            <span style={{
              width: 7, height: 7, borderRadius: '50%',
              background: item.color, flexShrink: 0,
              boxShadow: isActive ? `0 0 6px ${item.color}` : 'none',
            }} />
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

  useEffect(() => {
    const handler = e => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [onClose])

  return createPortal(
    <div
      style={{
        position: 'fixed', inset: 0, zIndex: 9999,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        background: 'rgba(0,0,0,0.88)',
        backdropFilter: 'blur(12px)',
        WebkitBackdropFilter: 'blur(12px)',
        padding: '20px',
      }}
      onClick={onClose}
    >
      <div
        style={{
          position: 'relative', display: 'flex', flexDirection: 'column',
          // Responsive: up to 960px wide, up to 88% of viewport height
          width: 'min(960px, 100%)',
          height: 'min(760px, 88vh)',
          background: '#080d1a',
          border: '1px solid rgba(96,165,250,0.15)',
          borderRadius: 10,
          boxShadow: '0 0 0 1px rgba(255,255,255,0.04), 0 40px 80px rgba(0,0,0,0.75), 0 0 60px rgba(96,165,250,0.07)',
          overflow: 'hidden',
        }}
        onClick={e => e.stopPropagation()}
      >
        {/* Top SG red accent stripe */}
        <div style={{ height: 2, background: 'linear-gradient(90deg, #E3000B 0%, rgba(227,0,11,0.3) 60%, transparent 100%)', flexShrink: 0 }} />

        {/* Subtle grid scan-line overlay */}
        <div style={{
          position: 'absolute', inset: 0, pointerEvents: 'none', zIndex: 0,
          backgroundImage: 'linear-gradient(rgba(96,165,250,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(96,165,250,0.03) 1px, transparent 1px)',
          backgroundSize: '40px 40px',
        }} />

        {/* Content — fills remaining space */}
        <div style={{ position: 'relative', zIndex: 1, display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0, padding: '18px 22px 14px' }}>

          {/* Header */}
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 14, flexShrink: 0 }}>
            <div>
              <div style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.14em', color: '#E3000B', marginBottom: 5 }}>
                ◈ LATERAL MOVEMENT GRAPH
              </div>
              <div style={{ fontSize: 17, fontWeight: 700, color: '#e2e8f0', letterSpacing: '-0.01em' }}>{username}</div>
            </div>
            <button
              onClick={onClose}
              style={{
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                width: 32, height: 32, borderRadius: 6,
                border: '1px solid rgba(255,255,255,0.10)',
                background: 'rgba(255,255,255,0.03)',
                color: '#64748b', cursor: 'pointer',
                transition: 'all 150ms ease', flexShrink: 0,
              }}
              onMouseEnter={e => { e.currentTarget.style.borderColor = 'rgba(227,0,11,0.5)'; e.currentTarget.style.color = '#fca5a5' }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.10)'; e.currentTarget.style.color = '#64748b' }}
            >
              <X size={14} />
            </button>
          </div>

          {/* Graph area — flex:1 means it fills all remaining vertical space */}
          <div style={{
            flex: 1, minHeight: 0, borderRadius: 6, overflow: 'hidden',
            border: '1px solid rgba(96,165,250,0.10)',
            background: 'radial-gradient(ellipse at 50% 50%, #0d1a33 0%, #060b15 100%)',
            boxShadow: 'inset 0 0 40px rgba(0,0,0,0.4)',
            position: 'relative',
          }}>
            {/* Corner brackets */}
            {['top-left','top-right','bottom-left','bottom-right'].map(corner => {
              const [v, h] = corner.split('-')
              return (
                <div key={corner} style={{
                  position: 'absolute', [v]: 8, [h]: 8,
                  width: 12, height: 12,
                  borderTop:    v === 'top'    ? '1.5px solid rgba(227,0,11,0.5)' : 'none',
                  borderBottom: v === 'bottom' ? '1.5px solid rgba(227,0,11,0.5)' : 'none',
                  borderLeft:   h === 'left'   ? '1.5px solid rgba(227,0,11,0.5)' : 'none',
                  borderRight:  h === 'right'  ? '1.5px solid rgba(227,0,11,0.5)' : 'none',
                  pointerEvents: 'none', zIndex: 2,
                }} />
              )
            })}
            {/* BreachGraph fills 100% of this container (via ResizeObserver) */}
            <BreachGraph
              breachData={breachData}
              username={username}
              interactive={true}
              activeFilter={activeFilter}
              onFilterChange={setActiveFilter}
            />
          </div>

          {/* Interactive legend — horizontal, wraps naturally */}
          <GraphLegend activeFilter={activeFilter} onFilterChange={setActiveFilter} />

          <p style={{ marginTop: 8, textAlign: 'center', fontSize: 10, color: '#334155', letterSpacing: '0.04em' }}>
            Click a legend item to highlight · Hover nodes for details · Press Esc to close
          </p>
        </div>
      </div>
    </div>,
    document.body
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
      <section className="card slide-up" style={{ padding: 14, flexShrink: 0 }}>

        {/* Section label */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.09em', color: 'var(--text-muted)', marginBottom: 10 }}>
          <AlertTriangle size={11} style={{ color: 'var(--c-critical)' }} /> Breach Impact
        </div>

        {/* Loading */}
        {loading && (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 96, fontSize: 13, color: 'var(--text-muted)' }}>
            Simulating breach paths…
          </div>
        )}

        {/* Error */}
        {!loading && error && (
          <div style={{ borderRadius: 4, border: '1px solid var(--c-critical-bd)', background: 'var(--c-critical-bg)', padding: '8px 10px', fontSize: 12, color: 'var(--c-critical)' }}>
            {error}
          </div>
        )}

        {/* Content */}
        {!loading && !error && breachData && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>

            {/* Impact header row */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: 8 }}>
              <div style={{ borderRadius: 4, border: '1px solid var(--border)', background: 'var(--surface-mid)', padding: '10px 12px' }}>
                <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 6 }}>Estimated Impact</div>
                <span className={IMPACT_BADGE_CLS[breachData.estimated_impact] || 'badge-neutral'}>
                  {breachData.estimated_impact}
                </span>
                <div style={{ marginTop: 8, fontSize: 11, color: 'var(--text-secondary)' }}>
                  {breachData.pivot_user_count} users reachable
                </div>
              </div>

              <div style={{ borderRadius: 4, border: '1px solid var(--border)', background: 'var(--surface-mid)', padding: '10px 12px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 6 }}>
                  <span>Data Sensitivity Score</span>
                  <span style={{ color: 'var(--text-secondary)' }}>{Number(breachData.data_sensitivity_score).toFixed(1)} / 100</span>
                </div>
                <div className="risk-bar">
                  <div
                    className="risk-bar-fill"
                    style={{ width: `${breachData.data_sensitivity_score}%`, background: IMPACT_BAR_COLOR[breachData.estimated_impact] || 'var(--c-normal)' }}
                  />
                </div>
                <div style={{ marginTop: 8, fontSize: 11, color: 'var(--text-secondary)' }}>
                  {breachData.lateral_movement_risk?.length || 0} systems in lateral reach
                </div>
              </div>
            </div>

            {/* Collapsed graph */}
            <div style={{
              borderRadius: 6,
              border: '1px solid rgba(96,165,250,0.12)',
              background: 'radial-gradient(ellipse at 50% 50%, #0d1a33 0%, #060b15 100%)',
              padding: '10px 12px',
              position: 'relative',
              overflow: 'hidden',
            }}>
              {/* grid texture */}
              <div style={{
                position: 'absolute', inset: 0, pointerEvents: 'none',
                backgroundImage: 'linear-gradient(rgba(96,165,250,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(96,165,250,0.03) 1px, transparent 1px)',
                backgroundSize: '30px 30px',
              }} />

              {/* Corner brackets */}
              {['top-left','top-right','bottom-left','bottom-right'].map(corner => {
                const [v, h] = corner.split('-')
                return (
                  <div key={corner} style={{
                    position: 'absolute',
                    [v]: 6, [h]: 6,
                    width: 9, height: 9,
                    borderTop:    v === 'top'    ? '1.5px solid rgba(227,0,11,0.55)' : 'none',
                    borderBottom: v === 'bottom' ? '1.5px solid rgba(227,0,11,0.55)' : 'none',
                    borderLeft:   h === 'left'   ? '1.5px solid rgba(227,0,11,0.55)' : 'none',
                    borderRight:  h === 'right'  ? '1.5px solid rgba(227,0,11,0.55)' : 'none',
                    pointerEvents: 'none', zIndex: 2,
                  }} />
                )
              })}

              <div style={{ position: 'relative', zIndex: 1 }}>
                <div style={{ fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.12em', color: '#E3000B', marginBottom: 8, fontWeight: 600, opacity: 0.85 }}>
                  ◈ Attack Path Preview
                </div>
                <BreachGraph
                  breachData={breachData}
                  username={user.username}
                  height={200}
                  interactive={false}
                  activeFilter={null}
                  onFilterChange={() => {}}
                />

                {/* Static mini legend */}
                <div style={{ marginTop: 8, display: 'flex', flexWrap: 'wrap', gap: 10, fontSize: 10, color: '#475569' }}>
                  {LEGEND_ITEMS.map(item => (
                    <span key={item.key} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                      <span style={{ width: 6, height: 6, borderRadius: '50%', background: item.color, boxShadow: `0 0 4px ${item.color}88`, flexShrink: 0 }} />
                      <span style={{ color: '#64748b' }}>{item.label}</span>
                    </span>
                  ))}
                </div>

                {/* Expand button */}
                <button
                  onClick={e => { e.stopPropagation(); setShowModal(true) }}
                  style={{
                    width: '100%', marginTop: 12, height: 32, cursor: 'pointer',
                    display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
                    background: 'rgba(227,0,11,0.08)',
                    border: '1px solid rgba(227,0,11,0.25)',
                    borderRadius: 4, color: '#fca5a5',
                    fontSize: 11, fontWeight: 600,
                    letterSpacing: '0.04em',
                    transition: 'all 150ms ease',
                  }}
                  onMouseEnter={e => { e.currentTarget.style.background = 'rgba(227,0,11,0.16)'; e.currentTarget.style.borderColor = 'rgba(227,0,11,0.5)'; e.currentTarget.style.color = '#fff' }}
                  onMouseLeave={e => { e.currentTarget.style.background = 'rgba(227,0,11,0.08)'; e.currentTarget.style.borderColor = 'rgba(227,0,11,0.25)'; e.currentTarget.style.color = '#fca5a5' }}
                >
                  View Full Graph ↗
                </button>
              </div>
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
