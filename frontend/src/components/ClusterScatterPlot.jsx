import { useEffect, useRef, useState } from 'react'

// ── Cluster identity ──────────────────────────────────────────────────────────
// One color per cluster label — must stay consistent with backend CLUSTER_DESCRIPTIONS
const CLUSTER_COLORS = {
  0: '#22d3ee',  // cyan   — Normal business hours actor
  1: '#f43f5e',  // rose   — High-frequency night actor
  2: '#f97316',  // orange — Bulk exporter
  3: '#a855f7',  // purple — Admin operation heavy
  4: '#eab308',  // yellow — Mixed anomalous pattern
}

const CLUSTER_LABELS = {
  0: 'Normal',
  1: 'Night Actor',
  2: 'Bulk Exporter',
  3: 'Admin Heavy',
  4: 'Mixed Anomalous',
}

// ── D3 loader (same CDN pattern as BreachImpactPanel) ────────────────────────
function loadD3() {
  if (window.d3) return Promise.resolve(window.d3)
  return new Promise((resolve, reject) => {
    const existing = document.querySelector('script[data-d3="true"]')
    if (existing) {
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

// ── User popup shown on click ─────────────────────────────────────────────────
function UserPopup({ user, x, y, containerW, onClose, onInspect }) {
  if (!user) return null

  // Flip to left side if too close to right edge
  const flip = x > containerW - 220
  const left = flip ? x - 210 : x + 14

  const color = CLUSTER_COLORS[user.cluster_label] ?? '#94a3b8'

  return (
    <div
      className="pointer-events-auto absolute z-20 w-52 rounded-2xl border border-white/10 bg-slate-900/98 p-4 shadow-2xl backdrop-blur"
      style={{ left, top: Math.max(8, y - 20) }}
    >
      {/* Close */}
      <button
        onClick={onClose}
        className="absolute right-3 top-3 text-slate-500 hover:text-white"
      >
        <svg className="h-3 w-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
        </svg>
      </button>

      {/* Cluster color strip */}
      <div className="mb-3 h-0.5 w-8 rounded-full" style={{ background: color }} />

      <div className="text-sm font-semibold text-white leading-tight">{user.username}</div>
      <div className="mt-0.5 font-mono text-[10px] text-slate-500">{user.user_id}</div>

      <div className="mt-3 space-y-1.5 text-[11px]">
        <Row label="Department"  value={user.department} />
        <Row label="Privilege"   value={user.privilege_level} />
        <Row label="Risk Score"  value={Number(user.risk_score).toFixed(1)} highlight />
        <Row label="After-Hours" value={`${(user.after_hours_ratio * 100).toFixed(0)}%`} />
        <Row label="Cluster"     value={CLUSTER_LABELS[user.cluster_label] ?? `#${user.cluster_label}`} />
      </div>

      {/* Flags */}
      {(user.flags || []).length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1">
          {user.flags.slice(0, 3).map(f => (
            <span
              key={f}
              className="chip border border-white/10 bg-white/5 text-[9px] text-slate-400"
            >
              {f.replace(/_/g, ' ')}
            </span>
          ))}
          {user.flags.length > 3 && (
            <span className="chip border border-white/10 bg-white/5 text-[9px] text-slate-500">
              +{user.flags.length - 3}
            </span>
          )}
        </div>
      )}

      {/* Inspect button */}
      <button
        onClick={() => { onInspect(user); onClose() }}
        className="mt-3 w-full rounded-xl border border-cyan-500/30 bg-cyan-500/10 py-1.5 text-[11px] font-medium text-cyan-300 transition hover:bg-cyan-500/20"
      >
        Inspect User →
      </button>
    </div>
  )
}

function Row({ label, value, highlight }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-slate-500">{label}</span>
      <span className={highlight ? 'font-semibold text-white' : 'text-slate-300'}>{value}</span>
    </div>
  )
}

// ── Main scatter plot ─────────────────────────────────────────────────────────

export default function ClusterScatterPlot({ users, onSelectUser }) {
  const svgRef       = useRef(null)
  const containerRef = useRef(null)
  const zoomRef      = useRef(null)

  // activeCluster: null = show all, number = highlight that cluster
  const [activeCluster, setActiveCluster] = useState(null)
  // popup state
  const [popup, setPopup] = useState({ visible: false, user: null, x: 0, y: 0 })

  const MARGIN = { top: 20, right: 24, bottom: 48, left: 52 }

  // Helper to compute base radius for a datum
  const baseRadius = (d, active) => {
    const base = (d.flags?.length > 0) ? 7 : 5
    return active !== null && d.cluster_label === active ? base + 2 : base
  }

  // ── Render D3 chart ─────────────────────────────────────────────────────────
  useEffect(() => {
    if (!users?.length || !svgRef.current || !containerRef.current) return
    let cancelled = false

    const render = async () => {
      const d3 = await loadD3()
      if (cancelled || !svgRef.current || !containerRef.current) return

      const totalW = containerRef.current.clientWidth || 700
      const totalH = 340
      const W = totalW - MARGIN.left - MARGIN.right
      const H = totalH - MARGIN.top  - MARGIN.bottom
      const usersWithJitter = users.map((u, idx) => ({
        ...u,
        _jitter: ((idx * 17) % 11) - 5
      }))

      const svg = d3.select(svgRef.current)
      svg.selectAll('*').remove()
      svg
        .attr('viewBox', `0 0 ${totalW} ${totalH}`)
        .attr('preserveAspectRatio', 'xMidYMid meet')

      const g = svg.append('g').attr('transform', `translate(${MARGIN.left},${MARGIN.top})`)

      const zoomLayer = g.append('g').attr('class', 'zoom-layer')

      // ── Scales ──
      const xScale = d3.scaleLinear().domain([0, 1]).range([0, W])
      const yScale = d3.scaleLinear().domain([0, 100]).range([H, 0])

      // ── Clip path so zoomed content doesn't overflow the chart area ──
      const clipId = 'cluster-scatter-clip'
      svg.append('defs').append('clipPath')
        .attr('id', clipId)
        .append('rect')
        .attr('width', W)
        .attr('height', H)

      zoomLayer.attr('clip-path', `url(#${clipId})`)

      // ── Grid lines ──
      zoomLayer.append('g').attr('class', 'grid-h')
        .selectAll('line')
        .data(yScale.ticks(5))
        .enter().append('line')
        .attr('x1', 0).attr('x2', W)
        .attr('y1', d => yScale(d)).attr('y2', d => yScale(d))
        .attr('stroke', 'rgba(255,255,255,0.05)')
        .attr('stroke-width', 1)

      zoomLayer.append('g').attr('class', 'grid-v')
        .selectAll('line')
        .data(xScale.ticks(5))
        .enter().append('line')
        .attr('x1', d => xScale(d)).attr('x2', d => xScale(d))
        .attr('y1', 0).attr('y2', H)
        .attr('stroke', 'rgba(255,255,255,0.05)')
        .attr('stroke-width', 1)

      // ── Axes ──
      const xAxis = d3.axisBottom(xScale)
        .ticks(5)
        .tickFormat(d => `${(d * 100).toFixed(0)}%`)

      const yAxis = d3.axisLeft(yScale)
        .ticks(5)

      g.append('g')
        .attr('transform', `translate(0,${H})`)
        .call(xAxis)
        .call(ax => {
          ax.select('.domain').attr('stroke', 'rgba(255,255,255,0.1)')
          ax.selectAll('.tick line').attr('stroke', 'rgba(255,255,255,0.08)')
          ax.selectAll('.tick text').attr('fill', '#475569').attr('font-size', '10px')
        })

      g.append('g')
        .call(yAxis)
        .call(ax => {
          ax.select('.domain').attr('stroke', 'rgba(255,255,255,0.1)')
          ax.selectAll('.tick line').attr('stroke', 'rgba(255,255,255,0.08)')
          ax.selectAll('.tick text').attr('fill', '#475569').attr('font-size', '10px')
        })

      // ── Axis labels ──
      g.append('text')
        .attr('x', W / 2)
        .attr('y', H + 38)
        .attr('text-anchor', 'middle')
        .attr('fill', '#64748b')
        .attr('font-size', '11px')
        .text('After-Hours Activity →')

      g.append('text')
        .attr('transform', 'rotate(-90)')
        .attr('x', -H / 2)
        .attr('y', -40)
        .attr('text-anchor', 'middle')
        .attr('fill', '#64748b')
        .attr('font-size', '11px')
        .text('← Risk Score')

      // ── Dots ──
      const dots = zoomLayer.append('g').attr('class', 'dots')
        .selectAll('circle')
        .data(usersWithJitter)
        .enter()
        .append('circle')
        .attr('cx', d => xScale(d.after_hours_ratio ?? 0) + d._jitter)
        .attr('cy', d => yScale(d.risk_score ?? 0))
        .attr('r',  d => baseRadius(d, activeCluster))
        .attr('fill',         d => CLUSTER_COLORS[d.cluster_label] ?? '#94a3b8')
        .attr('fill-opacity', d => activeCluster === null || d.cluster_label === activeCluster ? 0.75 : 0.08)
        .attr('stroke',       d => CLUSTER_COLORS[d.cluster_label] ?? '#94a3b8')
        .attr('stroke-width', 1)
        .attr('stroke-opacity', d => activeCluster === null || d.cluster_label === activeCluster ? 1 : 0.05)
        .style('cursor', 'pointer')
        .on('click', (event, d) => {
          event.stopPropagation()

          const rect = containerRef.current.getBoundingClientRect()

          setPopup({
            visible: true,
            user: d,
            x: event.clientX - rect.left,
            y: event.clientY - rect.top,
          })
        })

      // ── Zoom: translate/scale the layer, but counter-scale dot
      //     radius & stroke-width so points stay a constant visual size ──
      const zoom = d3.zoom()
        .scaleExtent([1, 8])
        .extent([[0, 0], [W, H]])
        .translateExtent([[0, 0], [W, H]])
        .on('zoom', (event) => {
          const { transform } = event
          zoomLayer.attr('transform', transform)

          const k = transform.k
          zoomLayer.selectAll('.dots circle')
            .attr('r', d => baseRadius(d, activeCluster) / k)
            .attr('stroke-width', 1 / k)

          // keep grid lines visually thin too
          zoomLayer.selectAll('.grid-h line, .grid-v line')
            .attr('stroke-width', 1 / k)
        })

      zoomRef.current = zoom

      svg.call(zoom)

      // Click outside to close popup
      svg.on('click', () => setPopup(p => ({ ...p, visible: false, user: null })))
    }

    render()
    return () => { cancelled = true }
  }, [users])

  // ── Filter effect — updates dot opacity/size when activeCluster changes ─────
  useEffect(() => {
    if (!svgRef.current) return
    const d3 = window.d3
    if (!d3) return

    const svg = d3.select(svgRef.current)
    const zoomLayer = svg.select('.zoom-layer')

    // Read current zoom scale so we keep radii correctly counter-scaled
    let k = 1
    try {
      const t = d3.zoomTransform(svgRef.current)
      k = t.k || 1
    } catch (e) {
      k = 1
    }

    zoomLayer.selectAll('.dots circle')
      .transition().duration(180)
      .attr('fill-opacity',   d => activeCluster === null || d.cluster_label === activeCluster ? 0.85 : 0.08)
      .attr('stroke-opacity', d => activeCluster === null || d.cluster_label === activeCluster ? 1    : 0.05)
      .attr('r',              d => baseRadius(d, activeCluster) / k)
  }, [activeCluster])

  // Unique cluster labels present in data
  const presentClusters = [...new Set((users || []).map(u => u.cluster_label))]
    .filter(c => c !== undefined && c !== null)
    .sort()

  return (
    <div className="space-y-3">
      {/* Interactive cluster legend */}
      <div className="flex flex-wrap gap-2">
        {presentClusters.map(label => {
          const color   = CLUSTER_COLORS[label] ?? '#94a3b8'
          const isActive = activeCluster === label
          return (
            <button
              key={label}
              onClick={() => setActiveCluster(isActive ? null : label)}
              className={`flex items-center gap-2 rounded-full border px-3 py-1 text-[11px] font-medium transition ${
                isActive
                  ? 'border-white/30 bg-white/10 text-white'
                  : 'border-white/10 bg-white/5 text-slate-400 hover:border-white/20 hover:text-slate-200'
              }`}
            >
              <span className="h-2 w-2 rounded-full" style={{ background: color }} />
              {CLUSTER_LABELS[label] ?? `Cluster ${label}`}
            </button>
          )
        })}
        {activeCluster !== null && (
          <button
            onClick={() => setActiveCluster(null)}
            className="rounded-full border border-white/10 bg-white/5 px-3 py-1 text-[11px] text-slate-500 transition hover:text-slate-300"
          >
            Show all
          </button>
        )}
      </div>

      {/* Reset button */}
      <div className="flex justify-end">
        <button
          onClick={() => {
            const d3 = window.d3
            if (!d3 || !zoomRef.current) return

            d3.select(svgRef.current)
              .transition()
              .duration(400)
              .call(
                zoomRef.current.transform,
                d3.zoomIdentity
              )
          }}
          className="rounded-lg border border-white/10 bg-white/5 px-3 py-1 text-xs text-slate-400 hover:text-white"
        >
          Reset View
        </button>
      </div>

      {/* Chart container */}
      <div ref={containerRef} className="relative w-full rounded-2xl border border-white/8 bg-black/30 p-2">
        <svg ref={svgRef} className="w-full" style={{ height: 340 }} />

        {/* User popup */}
        {popup.visible && popup.user && (
          <UserPopup
            user={popup.user}
            x={popup.x}
            y={popup.y}
            containerW={containerRef.current?.clientWidth ?? 700}
            onClose={() => setPopup(p => ({ ...p, visible: false, user: null }))}
            onInspect={onSelectUser}
          />
        )}
      </div>

      <p className="text-center text-[10px] text-slate-600">
        Click any point to see user details · Click a cluster label to highlight · Scroll/pinch to zoom
      </p>
    </div>
  )
}