import { useState, useEffect, useRef } from 'react'
import * as d3 from 'd3'
import {
  Shield,
  ShieldAlert,
  Flame,
  Zap,
  Target,
  Layers,
  ChevronRight,
  RefreshCw,
  Search,
  Activity,
  Sliders,
  CheckCircle,
  AlertTriangle,
  FileText,
  CornerDownRight
} from 'lucide-react'

export default function GraphView({ selectedAccount = 'USR00173', onNavigateToRemediation }) {
  const svgRef = useRef(null)
  const [graphData, setGraphData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [focusQuery, setFocusQuery] = useState(selectedAccount || 'USR00173')
  const [activeFocus, setActiveFocus] = useState(selectedAccount || 'USR00173')
  const [depth, setDepth] = useState(3)
  const [selectedNode, setSelectedNode] = useState(null)

  // Simulation & What-If State
  const [simulating, setSimulating] = useState(false)
  const [simResults, setSimResults] = useState(null)
  const [whatIfResults, setWhatIfResults] = useState(null)
  const [stagedRevocations, setStagedRevocations] = useState([])
  const [addedToQueue, setAddedToQueue] = useState(false)

  // 1. Fetch Graph Subgraph
  const fetchGraph = (focusId, hopDepth) => {
    setLoading(true)
    const url = focusId
      ? `/api/graph?focus=${encodeURIComponent(focusId)}&depth=${hopDepth}`
      : `/api/graph?depth=${hopDepth}`

    fetch(url)
      .then(res => res.json())
      .then(data => {
        if (data.status === 'success') {
          setGraphData(data)
          // Default selection to first node or focus node
          const match = data.nodes.find(n => n.id.includes(focusId)) || data.nodes[0]
          setSelectedNode(match || null)
        }
      })
      .catch(e => console.error('Failed to load graph:', e))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    fetchGraph(activeFocus, depth)
  }, [activeFocus, depth])

  // 2. Simulate Compromise
  const runSimulateCompromise = (nodeId) => {
    if (!nodeId) return
    setSimulating(true)
    fetch('/api/graph/simulate-compromise', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ account_id: nodeId, max_depth: 4 }),
    })
      .then(res => res.json())
      .then(data => {
        if (data.status === 'success') {
          setSimResults(data)
        }
      })
      .catch(e => console.error('Simulation error:', e))
      .finally(() => setSimulating(false))
  }

  // 3. Stage What-If Revoke
  const handleToggleRevoke = (entitlementName, accountId) => {
    const exists = stagedRevocations.some(
      r => r.entitlement === entitlementName && r.account_id === accountId
    )
    let updated
    if (exists) {
      updated = stagedRevocations.filter(
        r => !(r.entitlement === entitlementName && r.account_id === accountId)
      )
    } else {
      updated = [...stagedRevocations, { account_id: accountId, entitlement: entitlementName }]
    }
    setStagedRevocations(updated)

    if (updated.length > 0) {
      fetch('/api/graph/whatif', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ revocations: updated, replay_days: 60 }),
      })
        .then(res => res.json())
        .then(data => {
          if (data.status === 'success') setWhatIfResults(data)
        })
    } else {
      setWhatIfResults(null)
    }
  }

  // 4. Submit to Remediation Queue
  const submitToRemediationQueue = () => {
    if (!whatIfResults || !whatIfResults.revocations) return
    const promises = whatIfResults.revocations.map(rev =>
      fetch('/api/remediation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_identity: selectedNode?.label || rev.account_id,
          target_account: rev.account_id,
          target_system: rev.system,
          action_type: 'revoke_entitlement',
          entitlement: rev.entitlement,
          reason: `What-If Analysis: ${whatIfResults.metrics.blast_reduction_percentage}% blast reduction. ${rev.impact_summary}`,
          risk_severity: rev.classification === 'safe' ? 'medium' : 'high',
          impact_classification: rev.classification,
        }),
      })
    )

    Promise.all(promises).then(() => {
      setAddedToQueue(true)
      setTimeout(() => setAddedToQueue(false), 3000)
    })
  }

  // 5. Render D3 Force-Directed Graph
  useEffect(() => {
    if (!graphData || !svgRef.current) return

    const width = 800
    const height = 600
    const svg = d3.select(svgRef.current)
    svg.selectAll('*').remove()

    const gContainer = svg.append('g')

    // Zoom behavior
    const zoom = d3.zoom()
      .scaleExtent([0.3, 3])
      .on('zoom', (event) => gContainer.attr('transform', event.transform))
    svg.call(zoom)

    // Node colors by type
    const accentColor = getComputedStyle(document.documentElement).getPropertyValue('--accent').trim() || '#00E5FF'
    const colorByType = {
      identity: accentColor,
      account: '#6366F1',      // Indigo
      entitlement: '#F59E0B',  // Amber
      system: '#A855F7',       // Purple
      resource: '#DC2626',     // Crimson
    }

    const nodes = graphData.nodes.map(d => ({ ...d }))
    const links = graphData.links.map(d => ({ ...d }))

    // Simulation
    const simulation = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id(d => d.id).distance(65))
      .force('charge', d3.forceManyBody().strength(-180))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(25))

    // Arrow marker
    svg.append('defs').selectAll('marker')
      .data(['end'])
      .enter().append('marker')
      .attr('id', 'arrow')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 18)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('fill', '#334155')
      .attr('d', 'M0,-5L10,0L0,5')

    // Links
    const link = gContainer.append('g')
      .selectAll('line')
      .data(links)
      .enter().append('line')
      .attr('stroke', '#1E293B')
      .attr('stroke-width', d => Math.max(1, 3 - (d.weight || 1)))
      .attr('marker-end', 'url(#arrow)')

    // Nodes
    const node = gContainer.append('g')
      .selectAll('g')
      .data(nodes)
      .enter().append('g')
      .call(d3.drag()
        .on('start', dragstarted)
        .on('drag', dragged)
        .on('end', dragended)
      )
      .on('click', (event, d) => {
        setSelectedNode(d)
        runSimulateCompromise(d.id)
      })

    // Node circles with glowing ring for crown jewels
    node.append('circle')
      .attr('r', d => (d.is_crown ? 14 : d.node_type === 'identity' ? 12 : 9))
      .attr('fill', d => d.is_crown ? '#EF4444' : (colorByType[d.node_type] || '#94A3B8'))
      .attr('stroke', d => d.is_crown ? '#FCA5A5' : '#0F172A')
      .attr('stroke-width', d => d.is_crown ? 3 : 1.5)
      .style('cursor', 'pointer')
      .style('filter', d => d.is_crown ? 'drop-shadow(0 0 6px rgba(239, 68, 68, 0.8))' : 'none')

    // Labels
    node.append('text')
      .attr('x', 14)
      .attr('y', 4)
      .text(d => d.label)
      .attr('fill', '#94A3B8')
      .attr('font-size', '10px')
      .attr('font-family', 'monospace')
      .style('pointer-events', 'none')

    simulation.on('tick', () => {
      link
        .attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x)
        .attr('y2', d => d.target.y)

      node.attr('transform', d => `translate(${d.x},${d.y})`)
    })

    function dragstarted(event) {
      if (!event.active) simulation.alphaTarget(0.3).restart()
      event.subject.fx = event.subject.x
      event.subject.fy = event.subject.y
    }
    function dragged(event) {
      event.subject.fx = event.x
      event.subject.fy = event.y
    }
    function dragended(event) {
      if (!event.active) simulation.alphaTarget(0)
      event.subject.fx = null
      event.subject.fy = null
    }

    return () => simulation.stop()
  }, [graphData])

  return (
    <div style={{ display: 'flex', height: '100%', gap: 14, overflow: 'hidden' }}>
      {/* ── Left / Center: Interactive D3 Graph Canvas ── */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0, gap: 10 }}>
        {/* Top Control Toolbar */}
        <div className="card" style={{ padding: '10px 14px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1 }}>
            <Search size={14} color="var(--text-muted)" />
            <input
              type="text"
              placeholder="Search Identity or Account (e.g. USR00173, asmith)..."
              value={focusQuery}
              onChange={e => setFocusQuery(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && setActiveFocus(focusQuery)}
              style={{
                background: 'var(--surface-mid)', border: '1px solid var(--border)',
                borderRadius: 4, padding: '4px 10px', fontSize: 12, color: 'var(--text-primary)', width: 260
              }}
            />
            <button
              className="btn-primary"
              style={{ padding: '4px 10px', fontSize: 11 }}
              onClick={() => setActiveFocus(focusQuery)}
            >
              Focus Ego Net
            </button>
            <button
              className="btn-ghost"
              style={{ padding: '4px 8px', fontSize: 11 }}
              onClick={() => { setActiveFocus(null); setFocusQuery(''); }}
            >
              Reset Full Graph
            </button>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 11, color: 'var(--text-secondary)' }}>
            <span>Hops:</span>
            {[2, 3, 4].map(d => (
              <button
                key={d}
                onClick={() => setDepth(d)}
                style={{
                  padding: '2px 8px', borderRadius: 4, cursor: 'pointer',
                  background: depth === d ? '#6366F1' : 'var(--surface-mid)',
                  color: depth === d ? '#FFF' : 'var(--text-secondary)',
                  border: '1px solid var(--border)'
                }}
              >
                {d}
              </button>
            ))}
            <div style={{ borderLeft: '1px solid var(--border)', height: 16, margin: '0 4px' }} />
            <span className="mono" style={{ fontSize: 10 }}>
              {graphData ? `${graphData.subgraph_nodes} nodes · ${graphData.subgraph_edges} edges` : 'Loading...'}
            </span>
          </div>
        </div>

        {/* Graph Canvas Container */}
        <div className="card" style={{ flex: 1, position: 'relative', overflow: 'hidden', padding: 0 }}>
          <svg ref={svgRef} style={{ width: '100%', height: '100%', display: 'block', background: '#090D16' }} />

          {/* Graph Legend Overlay */}
          <div style={{
            position: 'absolute', bottom: 12, left: 12,
            background: 'var(--surface)', backdropFilter: 'blur(8px)',
            border: '1px solid var(--border)', borderRadius: 6, padding: '8px 12px',
            display: 'flex', gap: 14, fontSize: 11, color: 'var(--text-secondary)'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <span style={{ width: 9, height: 9, borderRadius: '50%', background: 'var(--accent)' }} /> Identity
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <span style={{ width: 9, height: 9, borderRadius: '50%', background: '#6366F1' }} /> Account
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <span style={{ width: 9, height: 9, borderRadius: '50%', background: '#F59E0B' }} /> Entitlement
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <span style={{ width: 9, height: 9, borderRadius: '50%', background: '#A855F7' }} /> System
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <span style={{ width: 11, height: 11, borderRadius: '50%', background: '#EF4444', boxShadow: '0 0 6px #EF4444' }} /> Crown Jewel
            </div>
          </div>
        </div>
      </div>

      {/* ── Right Panel: Blast Radius & What-If Analyzer ── */}
      <div style={{ width: 380, display: 'flex', flexDirection: 'column', gap: 10, overflowY: 'auto' }}>
        {/* Selected Node Header */}
        <div className="card" style={{ padding: 14 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
            <div>
              <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--text-muted)' }}>
                Target Entity Inspector
              </div>
              <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)', marginTop: 2 }}>
                {selectedNode?.label || 'Select a node'}
              </div>
              <div className="mono" style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                {selectedNode?.id || '—'}
              </div>
            </div>
            {selectedNode && (
              <span className={`flag-tag ${selectedNode.is_crown ? 'critical' : 'neutral'}`}>
                {selectedNode.node_type}
              </span>
            )}
          </div>

          {selectedNode && (
            <button
              className="btn-primary"
              style={{ width: '100%', justifyContent: 'center', gap: 6, marginTop: 8 }}
              onClick={() => runSimulateCompromise(selectedNode.id)}
              disabled={simulating}
            >
              <Flame size={13} />
              {simulating ? 'Simulating…' : 'Simulate Compromise'}
            </button>
          )}
        </div>

        {/* Blast Radius Scorecard */}
        {simResults && (
          <div className="card slide-up" style={{ padding: 14 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, fontWeight: 600, color: 'var(--text-primary)' }}>
                <Zap size={14} color="var(--accent)" /> Blast Radius Analysis
              </div>
              <div style={{
                fontSize: 14, fontWeight: 800,
                color: simResults.blast.blast_score > 60 ? '#EF4444' : simResults.blast.blast_score > 30 ? '#F59E0B' : '#10B981'
              }}>
                {simResults.blast.blast_score}/100
              </div>
            </div>

            {/* Reachable Assets Summary */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, marginBottom: 12 }}>
              <div style={{ background: 'var(--surface-mid)', padding: '6px 8px', borderRadius: 4, border: '1px solid var(--border)' }}>
                <div style={{ fontSize: 9, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Reachable Systems</div>
                <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', marginTop: 2 }}>
                  {simResults.blast.reachable_systems.length}
                </div>
              </div>
              <div style={{ background: 'var(--surface-mid)', padding: '6px 8px', borderRadius: 4, border: '1px solid var(--border)' }}>
                <div style={{ fontSize: 9, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Crown Jewels Reachable</div>
                <div style={{ fontSize: 14, fontWeight: 700, color: '#EF4444', marginTop: 2 }}>
                  {simResults.blast.crown_jewels.length}
                </div>
              </div>
            </div>

            {/* Reachable Crown Jewels List */}
            {simResults.blast.crown_jewels.length > 0 && (
              <div style={{ marginBottom: 12 }}>
                <div style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 4 }}>
                  Exposed Crown Jewel Assets:
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {simResults.blast.crown_jewels.map((cj, i) => (
                    <div key={i} style={{
                      fontSize: 11, padding: '4px 8px', borderRadius: 4,
                      background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)',
                      color: '#F87171', display: 'flex', justifyContent: 'space-between'
                    }}>
                      <span>{cj.name}</span>
                      <span className="mono" style={{ fontSize: 10 }}>{cj.hops} hops</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Attack Paths to Crown Jewels */}
            {simResults.attack_paths.length > 0 && (
              <div>
                <div style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 6 }}>
                  Shortest Lateral Attack Paths ({simResults.attack_paths.length})
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {simResults.attack_paths.map((p, idx) => (
                    <div key={idx} style={{
                      background: 'var(--surface-mid)', padding: 8, borderRadius: 4,
                      border: '1px solid var(--border)', fontSize: 11
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                        <span style={{ fontWeight: 600, color: '#EF4444' }}>Target: {p.target_name}</span>
                        <span className="mono" style={{ color: 'var(--text-muted)', fontSize: 10 }}>Cost: {p.total_cost}</span>
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 2, paddingLeft: 4 }}>
                        {p.hops.map((h, hi) => (
                          <div key={hi} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 10, color: 'var(--text-secondary)' }}>
                            <CornerDownRight size={10} color="#6366F1" />
                            <span>{h.from_label}</span>
                            <span style={{ color: 'var(--text-muted)' }}>({h.edge_type})</span>
                            <span>&rarr; {h.to_label}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* What-If Revoke Sandbox */}
        <div className="card" style={{ padding: 14 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 8 }}>
            <Sliders size={14} color="#F59E0B" /> What-If Revoke Sandbox
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 10 }}>
            Simulate removing high-risk entitlements to preview blast radius reduction and 60-day historical business disruption:
          </div>

          {/* Entitlement Toggles */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginBottom: 12 }}>
            {['AdministratorAccess', 'create_vendor', 'approve_payment', 'DB_CrownJewel_Exporter'].map(ent => {
              const active = stagedRevocations.some(r => r.entitlement === ent)
              return (
                <button
                  key={ent}
                  onClick={() => handleToggleRevoke(ent, selectedNode?.id?.replace('account:', '') || 'USR00173')}
                  style={{
                    padding: '6px 10px', borderRadius: 4, textAlign: 'left',
                    background: active ? 'rgba(245, 158, 11, 0.15)' : 'var(--surface-mid)',
                    border: `1px solid ${active ? '#F59E0B' : 'var(--border)'}`,
                    color: active ? '#F59E0B' : 'var(--text-primary)',
                    fontSize: 11, cursor: 'pointer', display: 'flex', justifyContent: 'space-between'
                  }}
                >
                  <span className="mono">{ent}</span>
                  <span style={{ fontSize: 10 }}>{active ? 'STAGED FOR REVOKE' : '+ Stage Revoke'}</span>
                </button>
              )
            })}
          </div>

          {/* What-If Results Summary */}
          {whatIfResults && (
            <div className="slide-up" style={{
              background: 'var(--surface-mid)', padding: 10, borderRadius: 6,
              border: '1px solid #10B981', marginBottom: 10
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                <span style={{ fontSize: 11, fontWeight: 700, color: '#10B981' }}>
                  Risk Reduction: -{whatIfResults.metrics.blast_reduction_percentage}%
                </span>
                <span className="mono" style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                  {whatIfResults.metrics.paths_eliminated} paths cut
                </span>
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                Historical Replay: <strong>{whatIfResults.metrics.total_business_actions_blocked}</strong> events impacted.
              </div>

              {/* Classification Badges */}
              <div style={{ marginTop: 8, display: 'flex', flexDirection: 'column', gap: 4 }}>
                {whatIfResults.revocations.map((r, ri) => (
                  <div key={ri} style={{ fontSize: 10, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span className="mono">{r.entitlement}</span>
                    <span className={`flag-tag ${r.classification === 'safe' ? 'safe' : r.classification === 'review' ? 'review' : 'critical'}`}>
                      {r.classification.toUpperCase()}
                    </span>
                  </div>
                ))}
              </div>

              {/* Add to Queue Button */}
              <button
                className="btn-primary"
                style={{ width: '100%', marginTop: 10, justifyContent: 'center', fontSize: 11 }}
                onClick={submitToRemediationQueue}
                disabled={addedToQueue}
              >
                {addedToQueue ? <CheckCircle size={12} /> : <FileText size={12} />}
                {addedToQueue ? 'Added to Remediation Queue!' : 'Add to Remediation Queue'}
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
