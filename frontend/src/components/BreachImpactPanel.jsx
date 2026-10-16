import { useEffect, useRef, useState } from 'react'
import { AlertTriangle } from 'lucide-react'
import { getBreachSimulation } from '../api'

const sensitivityColor = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#94a3b8',
}

const impactStyle = {
  CATASTROPHIC: 'border-rose-400/40 bg-rose-500/10 text-rose-300',
  SEVERE: 'border-orange-400/40 bg-orange-500/10 text-orange-300',
  MODERATE: 'border-yellow-400/40 bg-yellow-500/10 text-yellow-300',
  LOW: 'border-emerald-400/40 bg-emerald-500/10 text-emerald-300',
}

const impactGradient = {
  CATASTROPHIC: 'from-rose-500 to-red-600',
  SEVERE: 'from-orange-400 to-amber-500',
  MODERATE: 'from-yellow-400 to-amber-400',
  LOW: 'from-emerald-400 to-teal-500',
}

function truncateLabel(label) {
  if (!label) return ''
  return label.length > 10 ? `${label.slice(0, 10)}…` : label
}

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

function Badge({ impact }) {
  const cls = impactStyle[impact] || impactStyle.LOW
  return <span className={`chip border ${cls}`}>{impact}</span>
}

function BreachGraph({ breachData, username }) {
  const svgRef = useRef(null)
  const containerRef = useRef(null)

  useEffect(() => {
    if (!breachData || !svgRef.current || !containerRef.current) return undefined

    let simulation = null
    let cancelled = false

    const render = async () => {
      const d3 = await loadD3()
      if (cancelled || !svgRef.current || !containerRef.current) return

      const width = containerRef.current.clientWidth || 640
      const height = 280
      const svg = d3.select(svgRef.current)
      svg.selectAll('*').remove()
      svg.attr('viewBox', `0 0 ${width} ${height}`).attr('preserveAspectRatio', 'xMidYMid meet')

      const centerNode = {
        id: `user-${breachData.user_id}`,
        label: username || breachData.user_id,
        type: 'user',
        radius: 20,
        color: '#f43f5e',
      }

      const directNodes = (breachData.directly_accessible || []).map((item, index) => ({
        id: `direct-${item.system}-${index}`,
        label: item.system,
        type: 'direct',
        radius: 12,
        color: sensitivityColor[item.sensitivity] || sensitivityColor.low,
      }))

      const lateralNodes = (breachData.lateral_movement_risk || []).map((system, index) => ({
        id: `lateral-${system}-${index}`,
        label: system,
        type: 'lateral',
        radius: 10,
        color: '#6366f1',
      }))

      const nodes = [centerNode, ...directNodes, ...lateralNodes]

      const links = [
        ...directNodes.map(node => ({ source: centerNode.id, target: node.id, kind: 'direct' })),
        ...lateralNodes.map(node => ({ source: centerNode.id, target: node.id, kind: 'lateral' })),
      ]

      const linkSelection = svg.append('g').attr('stroke', '#334155').attr('stroke-opacity', 0.7)
        .selectAll('line')
        .data(links)
        .enter()
        .append('line')
        .attr('stroke-width', 1.5)
        .attr('stroke-dasharray', d => d.kind === 'lateral' ? '4,3' : '0')

      const nodeGroup = svg.append('g').selectAll('g').data(nodes).enter().append('g').style('cursor', 'default')

      nodeGroup.append('circle')
        .attr('r', d => d.radius)
        .attr('fill', d => d.color)
        .attr('stroke', d => d.type === 'lateral' ? '#a5b4fc' : 'rgba(255,255,255,0.2)')
        .attr('stroke-width', d => d.type === 'lateral' ? 1.5 : 1)
        .attr('stroke-dasharray', d => d.type === 'lateral' ? '3,2' : '0')

      nodeGroup.append('text')
        .text(d => truncateLabel(d.label))
        .attr('y', d => d.radius + 12)
        .attr('text-anchor', 'middle')
        .attr('font-size', '9px')
        .attr('fill', '#94a3b8')

      simulation = d3.forceSimulation(nodes)
        .force('link', d3.forceLink(links).id(d => d.id).distance(80).strength(0.5))
        .force('charge', d3.forceManyBody().strength(-200))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(30))

      simulation.on('tick', () => {
        linkSelection
          .attr('x1', d => d.source.x)
          .attr('y1', d => d.source.y)
          .attr('x2', d => d.target.x)
          .attr('y2', d => d.target.y)

        nodeGroup.attr('transform', d => `translate(${d.x},${d.y})`)
      })
    }

    render()

    return () => {
      cancelled = true
      if (simulation) simulation.stop()
    }
  }, [breachData, username])

  return (
    <div ref={containerRef} className="w-full">
      <svg ref={svgRef} className="h-[280px] w-full" />
    </div>
  )
}

export default function BreachImpactPanel({ user }) {
  const [breachData, setBreachData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    let active = true

    if (!user) {
      setBreachData(null)
      setLoading(false)
      setError('')
      return undefined
    }

    setLoading(true)
    setError('')
    setBreachData(null)

    getBreachSimulation(user.user_id)
      .then(data => {
        if (!active) return
        setBreachData(data)
      })
      .catch(() => {
        if (!active) return
        setError('Could not load breach simulation')
      })
      .finally(() => {
        if (!active) return
        setLoading(false)
      })

    return () => {
      active = false
    }
  }, [user])

  if (!user) return null

  return (
    <section className="glass rounded-2xl border border-white/10 p-5 slide-up">
      <div className="flex items-center gap-2 text-[11px] uppercase tracking-widest text-slate-500">
        <AlertTriangle size={12} className="text-rose-400" /> Breach Impact
      </div>

      {loading && (
        <div className="mt-4 flex h-40 items-center justify-center text-sm text-slate-500">
          Loading breach simulation...
        </div>
      )}

      {!loading && error && (
        <div className="mt-4 rounded-xl border border-rose-400/20 bg-rose-500/10 p-3 text-sm text-rose-300">
          {error}
        </div>
      )}

      {!loading && !error && breachData && (
        <div className="mt-4 space-y-4">
          <div className="grid gap-3 sm:grid-cols-3">
            <div className="rounded-2xl border border-white/10 bg-white/5 p-4 sm:col-span-1">
              <div className="text-[10px] uppercase tracking-widest text-slate-500">Estimated Impact</div>
              <div className="mt-2">
                <Badge impact={breachData.estimated_impact} />
              </div>
              <div className="mt-3 text-xs text-slate-400">
                {breachData.pivot_user_count} users reachable via lateral movement
              </div>
            </div>

            <div className="rounded-2xl border border-white/10 bg-white/5 p-4 sm:col-span-2">
              <div className="flex items-center justify-between text-[10px] uppercase tracking-widest text-slate-500">
                <span>Data Sensitivity Score</span>
                <span className="text-slate-300">{Number(breachData.data_sensitivity_score).toFixed(1)} / 100</span>
              </div>
              <div className="mt-3 risk-bar">
                <div className={`risk-bar-fill bg-gradient-to-r ${impactGradient[breachData.estimated_impact] || impactGradient.LOW}`} style={{ width: `${breachData.data_sensitivity_score}%` }} />
              </div>
              <div className="mt-4 text-xs text-slate-400">
                {breachData.pivot_user_ids?.length || 0} pivot users identified
              </div>
            </div>
          </div>

          <div className="rounded-2xl border border-white/10 bg-black/20 p-3">
            <BreachGraph breachData={breachData} username={user.username} />
            <div className="mt-3 flex flex-wrap gap-3 text-[10px] uppercase tracking-widest text-slate-500">
              <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-rose-500" /> Critical system</span>
              <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-orange-500" /> High sensitivity</span>
              <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-indigo-500" /> Lateral reach</span>
              <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-slate-500" /> User</span>
            </div>
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
              <div className="mb-3 text-[10px] uppercase tracking-widest text-slate-500">Direct Access</div>
              <div className="space-y-2">
                {(breachData.directly_accessible || []).map(item => (
                  <div key={item.system} className="flex items-center justify-between rounded-xl border border-white/10 bg-black/20 px-3 py-2 text-sm text-slate-200">
                    <span>{item.system}</span>
                    <span className="chip border border-white/10 bg-white/5 text-[10px] text-slate-300">
                      {item.sensitivity}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
              <div className="mb-3 text-[10px] uppercase tracking-widest text-slate-500">Lateral Reach</div>
              <div className="space-y-2">
                {(breachData.lateral_movement_risk || []).map(system => (
                  <div key={system} className="flex items-center justify-between rounded-xl border border-indigo-500/20 bg-indigo-500/10 px-3 py-2 text-sm text-indigo-200">
                    <span>{system}</span>
                    <span className="chip border border-indigo-400/30 bg-indigo-500/10 text-[10px] text-indigo-200">pivot</span>
                  </div>
                ))}
                {(breachData.lateral_movement_risk || []).length === 0 && (
                  <div className="text-sm text-slate-500">No lateral reach identified.</div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </section>
  )
}
