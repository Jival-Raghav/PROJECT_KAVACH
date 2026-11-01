import { lazy, Suspense, useMemo, useRef, useState } from 'react'
import { Box, Loader2, Workflow } from 'lucide-react'
import GraphCanvas from './GraphCanvas'

const Graph3D = lazy(() => import('./Graph3D'))

// Keep the same array identity while the graph content (ids, titles, tones, layout, pills) is unchanged, so a live refresh that
// brings identical data does not make the canvas re-fit or the 3D view re-layout.
const skip = (_k, v) => (typeof v === 'function' || (v && typeof v === 'object' && '$$typeof' in v) ? undefined : v)
const sig = (nodes, edges) => JSON.stringify([nodes, edges], skip)
function useStable(nodes, edges) {
  const s = sig(nodes, edges)
  const ref = useRef({ nodes, edges })
  return useMemo(() => { ref.current = { nodes, edges }; return ref.current }, [s]) // eslint-disable-line react-hooks/exhaustive-deps
}

/**
 * Same contract as GraphCanvas, with a 3D "knowledge graph" view by default and a flat fallback.
 * Pass nodes3d/edges3d when the 3D view should show a different (denser) graph than the flat one;
 * physics=true drops the reading-order column layout for a free-floating hub-and-cloud instead.
 */
export default function IncidentGraph({ nodes, edges, nodes3d, edges3d, physics, selected, onSelect, ariaLabel }) {
  const [mode, setMode] = useState(() => localStorage.getItem('kavach-graph-mode') || '3d')
  const flat = useStable(nodes, edges)
  const deep = useStable(nodes3d, edges3d)
  const set = m => { setMode(m); localStorage.setItem('kavach-graph-mode', m) }

  return (
    <div className="kc-graph-wrap">
      <div className="kc-view-toggle" role="tablist" aria-label="Graph view">
        <button role="tab" aria-selected={mode === '3d'} className={mode === '3d' ? 'on' : ''} onClick={() => set('3d')}>
          <Box size={13} /> 3D
        </button>
        <button role="tab" aria-selected={mode === '2d'} className={mode === '2d' ? 'on' : ''} onClick={() => set('2d')}>
          <Workflow size={13} /> Flat
        </button>
      </div>
      {mode === '3d'
        ? (
          <Suspense fallback={<div className="kc-canvas kc-canvas-3d kc-canvas-loading"><Loader2 size={22} className="spin-slow" /></div>}>
            <Graph3D nodes={nodes3d ? deep.nodes : flat.nodes} edges={edges3d ? deep.edges : flat.edges} physics={physics}
              selected={selected} onSelect={onSelect} ariaLabel={ariaLabel} />
          </Suspense>
        )
        : <GraphCanvas nodes={flat.nodes} edges={flat.edges} selected={selected} onSelect={onSelect} ariaLabel={ariaLabel} />}
    </div>
  )
}
