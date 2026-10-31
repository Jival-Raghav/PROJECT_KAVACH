import { useEffect, useMemo, useRef } from 'react'
import ForceGraph3D from '3d-force-graph'
import * as THREE from 'three'
import { UnrealBloomPass } from 'three/addons/postprocessing/UnrealBloomPass.js'
import SpriteText from 'three-spritetext'
import * as d3 from 'd3-force-3d'
import { Compass, Maximize, Orbit } from 'lucide-react'

// Brand tones, read once from CSS so the scene always matches the active theme.
function readPalette() {
  const s = getComputedStyle(document.documentElement)
  const v = (name, fallback) => (s.getPropertyValue(name).trim() || fallback)
  return {
    bad: v('--c-critical', '#F0705F'), warn: v('--c-review', '#FCD34D'),
    good: v('--c-normal', '#04DB7F'), info: v('--c-info', '#7DD3FC'),
    purple: '#A78BFA', plain: v('--text-muted', '#8B93A1'),
    text: v('--text-primary', '#F4F6F3'), dim: v('--text-muted', '#55606E'),
    bg: v('--bg-deep', '#05070A'),
  }
}

// Accepts any CSS color (hex, rgb(), rgba()) and normalizes via THREE.Color, so a theme var that
// isn't plain hex (e.g. --text-muted is rgba() in dark mode) never breaks the gradient.
function glowTexture(cssColor) {
  const { r, g: gc, b } = new THREE.Color(cssColor)
  const rgb = `${Math.round(r * 255)},${Math.round(gc * 255)},${Math.round(b * 255)}`
  const c = document.createElement('canvas')
  c.width = c.height = 128
  const ctx = c.getContext('2d')
  const g = ctx.createRadialGradient(64, 64, 0, 64, 64, 64)
  g.addColorStop(0, `rgba(${rgb},0.6)`)
  g.addColorStop(0.3, `rgba(${rgb},0.27)`)
  g.addColorStop(1, `rgba(${rgb},0)`)
  ctx.fillStyle = g
  ctx.fillRect(0, 0, 128, 128)
  const tex = new THREE.CanvasTexture(c)
  tex.needsUpdate = true
  return tex
}

function starfield(count = 600, spread = 2400) {
  const pos = new Float32Array(count * 3)
  for (let i = 0; i < count; i++) {
    pos[i * 3] = (Math.random() - 0.5) * spread
    pos[i * 3 + 1] = (Math.random() - 0.5) * spread
    pos[i * 3 + 2] = (Math.random() - 0.5) * spread
  }
  const geo = new THREE.BufferGeometry()
  geo.setAttribute('position', new THREE.BufferAttribute(pos, 3))
  return new THREE.Points(geo, new THREE.PointsMaterial({ color: 0x3a4250, size: 1.4, sizeAttenuation: true }))
}

/**
 * A 3D force-directed "knowledge graph" rendering of nodes/edges.
 * Props mirror GraphCanvas: nodes {id, col, title, sub, tone, size?}, edges {id, source, target, tone,
 * dashed, proven?}, selected, onSelect(id|null), ariaLabel.
 */
export default function Graph3D({ nodes, edges, selected, onSelect, ariaLabel, physics = false }) {
  const mountRef = useRef(null)
  const fgRef = useRef(null)
  const objRefs = useRef(new Map()) // node id -> { core, glow, label }
  const hoverRef = useRef({ node: null, link: null })
  const palette = useMemo(readPalette, [])
  const toneHex = tone => palette[tone] || palette.plain
  const selectedRef = useRef(selected)
  selectedRef.current = selected

  // ── Mount once ──────────────────────────────────────────────────────────
  useEffect(() => {
    const el = mountRef.current
    const fg = new ForceGraph3D(el, { controlType: 'orbit' })
      .backgroundColor('rgba(0,0,0,0)')
      .nodeRelSize(1)
      .nodeVal(n => n.size ?? (n.col === 0 ? 10 : 6))
      .nodeOpacity(1)
      .enableNodeDrag(false)
      .nodeThreeObjectExtend(false)
      .linkCurvature(0.18)
      .linkOpacity(0.5)
      .linkDirectionalParticleWidth(1.6)
      .linkDirectionalParticleSpeed(l => (l.tone === 'bad' ? 0.012 : 0.006))
      .onBackgroundClick(() => onSelect(null))
      .onNodeHover(n => { hoverRef.current.node = n?.id ?? null; applyHighlight() })
      .onLinkHover(l => { hoverRef.current.link = l?.id ?? null; applyHighlight() })
      .onNodeClick(n => {
        onSelect(n.id)
        const d = 90
        const r = 1 + d / Math.hypot(n.x || 1, n.y || 1, n.z || 1)
        fg.cameraPosition({ x: (n.x || 0) * r, y: (n.y || 0) * r, z: (n.z || 0) * r }, n, 700)
      })
      .onLinkClick(l => onSelect(l.id))
      .onEngineStop(() => fg.zoomToFit(600, 70))

    fg.scene().add(starfield())
    fg.scene().fog = new THREE.FogExp2(0x05070a, 0.0018)

    const dir = new THREE.DirectionalLight(0xffffff, 0.4)
    dir.position.set(200, 300, 250)
    fg.scene().add(dir, new THREE.AmbientLight(0x404a5a, 0.8))

    const composer = fg.postProcessingComposer()
    const bloom = new UnrealBloomPass(new THREE.Vector2(el.clientWidth || 800, el.clientHeight || 500), 0.32, 0.35, 0.32)
    composer.addPass(bloom)

    const controls = fg.controls()
    controls.autoRotate = true
    controls.autoRotateSpeed = 0.55
    let resumeTimer = null
    controls.addEventListener('start', () => {
      controls.autoRotate = false
      clearTimeout(resumeTimer)
    })
    controls.addEventListener('end', () => {
      clearTimeout(resumeTimer)
      resumeTimer = setTimeout(() => { controls.autoRotate = true }, 6000)
    })

    if (physics) {
      // A free-floating cloud: no reading-order bias, just a hub pulling its neighbours in.
      fg.d3Force('charge').strength(-34)
      fg.d3Force('link').distance(26).strength(0.9)
    } else {
      // Gentle column force so the attacker → target reading order survives the physics.
      fg.d3Force('x', d3.forceX(n => n.__colX ?? 0).strength(0.28))
      fg.d3Force('z', d3.forceZ(0).strength(0.12))
      fg.d3Force('charge').strength(-140)
    }
    fg.warmupTicks(physics ? 140 : 60).cooldownTicks(160)

    let pulse = 0
    fg.onEngineTick(() => {
      pulse += 0.045
      objRefs.current.forEach(({ core, glow }, id) => {
        const active = hoverRef.current.node === id || selectedRef.current === id
        const k = active ? 0.7 : 0.22 + 0.06 * Math.sin(pulse + id.length)
        if (core) core.material.emissiveIntensity = active ? 0.9 : k
        if (glow) glow.material.opacity = active ? 0.5 : 0.15 + 0.04 * Math.sin(pulse + id.length)
      })
    })

    const ro = new ResizeObserver(() => {
      const w = el.clientWidth, h = el.clientHeight
      if (!w || !h) return
      fg.width(w).height(h)
      bloom.setSize(w, h)
    })
    ro.observe(el)

    fgRef.current = fg
    return () => {
      ro.disconnect()
      clearTimeout(resumeTimer)
      fg._destructor?.()
      el.replaceChildren()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => { applyHighlight() }, [selected])

  function applyHighlight() {
    const fg = fgRef.current
    if (!fg) return
    const hoverId = hoverRef.current.node
    const hoverLinkId = hoverRef.current.link
    const anchor = hoverId || selectedRef.current
    const active = new Set()
    if (anchor) {
      active.add(anchor)
      edges.forEach(e => { if (e.source === anchor || e.target === anchor || e.id === anchor) { active.add(e.source); active.add(e.target) } })
    }
    const anyActive = active.size > 0
    objRefs.current.forEach(({ core, glow, label }, id) => {
      const on = !anyActive || active.has(id)
      if (core) core.material.opacity = on ? 1 : 0.22
      if (glow) glow.material.opacity = on ? (glow.material.opacity || 0.8) : 0.05
      if (label) label.material.opacity = on ? 1 : 0.25
    })
    fg.linkColor(l => {
      const on = !anyActive || active.has(l.source?.id ?? l.source) && active.has(l.target?.id ?? l.target)
        || l.id === hoverLinkId || l.id === selectedRef.current
      return on ? toneHex(l.tone) : palette.dim
    })
    fg.linkWidth(l => {
      const on = l.id === hoverLinkId || l.id === selectedRef.current
      return on ? 2.6 : 1.1
    })
    fg.linkDirectionalParticles(l => {
      if (l.dashed && l.tone !== 'bad') return anyActive && !(active.has(l.source?.id ?? l.source) && active.has(l.target?.id ?? l.target)) ? 0 : 2
      return anyActive && !(active.has(l.source?.id ?? l.source) && active.has(l.target?.id ?? l.target)) ? 0 : 4
    })
  }

  // ── Data updates ────────────────────────────────────────────────────────
  useEffect(() => {
    const fg = fgRef.current
    if (!fg) return
    let gNodes
    if (physics) {
      // A hub at the centre, everything else seeded in a loose shell so the simulation has
      // somewhere to spread it from — no artificial lanes.
      gNodes = nodes.map(n => {
        if (n.col === 0) return { ...n, x: 0, y: 0, z: 0 }
        const a = Math.random() * Math.PI * 2
        const b = Math.acos(2 * Math.random() - 1)
        const rad = 40 + n.col * 25
        return {
          ...n,
          x: rad * Math.sin(b) * Math.cos(a), y: rad * Math.sin(b) * Math.sin(a), z: rad * Math.cos(b),
        }
      })
    } else {
      const byCol = new Map()
      nodes.forEach(n => byCol.set(n.col, (byCol.get(n.col) || 0) + 1))
      const seen = new Map()
      gNodes = nodes.map(n => {
        const i = seen.get(n.col) || 0
        seen.set(n.col, i + 1)
        const spread = (byCol.get(n.col) || 1)
        return {
          ...n,
          __colX: n.col * 150,
          x: n.col * 150, y: (i - (spread - 1) / 2) * 46, z: (Math.random() - 0.5) * 40,
        }
      })
    }
    fg.nodeThreeObject(n => {
      const color = toneHex(n.tone)
      const r = n.size ?? (n.col === 0 ? 10 : 6)
      const group = new THREE.Group()
      const core = new THREE.Mesh(
        new THREE.SphereGeometry(r, 20, 20),
        new THREE.MeshStandardMaterial({ color, emissive: color, emissiveIntensity: 0.3, roughness: 0.5, metalness: 0.1, transparent: true }),
      )
      const glow = new THREE.Sprite(new THREE.SpriteMaterial({
        map: glowTexture(color), color, transparent: true, depthWrite: false, blending: THREE.AdditiveBlending, opacity: 0.22,
      }))
      glow.scale.set(r * 2.8, r * 2.8, 1)
      group.add(glow, core)
      let label = null
      if (n.showLabel !== false) {
        label = new SpriteText(n.title, r * 0.85, palette.text)
        label.fontWeight = '600'
        label.position.set(0, -(r + 9), 0)
        label.backgroundColor = false
        group.add(label)
      }
      objRefs.current.set(n.id, { core, glow, label })
      return group
    })
    fg.graphData({ nodes: gNodes, links: edges.map(e => ({ ...e })) })
    applyHighlight()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodes, edges])

  const fit = () => fgRef.current?.zoomToFit(500, 70)
  const toggleRotate = () => { const c = fgRef.current?.controls(); if (c) c.autoRotate = !c.autoRotate }

  return (
    <div className="kc-canvas kc-canvas-3d">
      <div className="kc-canvas-tools">
        <button onClick={fit} title="Zoom to fit" aria-label="Zoom to fit"><Maximize size={14} /></button>
        <button onClick={toggleRotate} title="Toggle auto-rotate" aria-label="Toggle auto-rotate"><Orbit size={14} /></button>
      </div>
      <div ref={mountRef} className="kc-canvas-3d-mount" role="img" aria-label={ariaLabel} />
      <div className="kc-canvas-hint"><Compass size={11} /> Drag to orbit · scroll to zoom · click a node or line</div>
    </div>
  )
}
