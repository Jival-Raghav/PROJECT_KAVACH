import { lazy, Suspense, useState } from 'react'
import { Box, Loader2, Workflow } from 'lucide-react'
import GraphCanvas from './GraphCanvas'

const Graph3D = lazy(() => import('./Graph3D'))

/**
 * Same contract as GraphCanvas, with a 3D "knowledge graph" view by default and a flat fallback.
 * Pass nodes3d/edges3d when the 3D view should show a different (denser) graph than the flat one;
 * physics=true drops the reading-order column layout for a free-floating hub-and-cloud instead.
 */
export default function IncidentGraph({ nodes, edges, nodes3d, edges3d, physics, selected, onSelect, ariaLabel }) {
  const [mode, setMode] = useState(() => localStorage.getItem('kavach-graph-mode') || '3d')
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
            <Graph3D nodes={nodes3d ?? nodes} edges={edges3d ?? edges} physics={physics}
              selected={selected} onSelect={onSelect} ariaLabel={ariaLabel} />
          </Suspense>
        )
        : <GraphCanvas nodes={nodes} edges={edges} selected={selected} onSelect={onSelect} ariaLabel={ariaLabel} />}
    </div>
  )
}
