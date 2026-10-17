import React, { useState, useEffect } from 'react'
import {
  GitMerge,
  Shield,
  Eye,
  Undo2,
  Redo2,
  RotateCcw,
  Plus,
  Play,
  Check,
  AlertTriangle,
  Loader2,
  FileCode2,
  Sparkles,
  GitCompare,
  ArrowLeft,
  X,
} from 'lucide-react'
import {
  proposeUnifiedSchema,
  getUnifiedSchema,
  patchUnifiedSchema,
  deriveFieldFromText,
  undoUnifiedSchema,
  redoUnifiedSchema,
  resetUnifiedSchema,
  diffUnifiedSchema,
  previewUnifiedSchema,
  createRun,
} from '../api'

const FIELD_ROLES = [
  'identifier',
  'timestamp',
  'actor',
  'action',
  'resource',
  'sensitivity',
  'privilege',
  'peer_group',
  'feature',
  'context_only',
  'label',
  'ignore',
]

export default function UnifiedSchemaView({ onBack, onRunComplete, sources }) {
  const [schema, setSchema] = useState(null)
  const [loading, setLoading] = useState(true)
  const [impact, setImpact] = useState(null)
  const [preview, setPreview] = useState(null)

  // Modals & Panels
  const [activeModal, setActiveModal] = useState(null) // 'describe' | 'expression' | 'promote' | 'diff'
  const [aiPrompt, setAiPrompt] = useState('')
  const [aiProposal, setAiProposal] = useState(null)
  const [aiLoading, setAiLoading] = useState(false)
  const [diffData, setDiffData] = useState(null)

  // Promotion / DSL state
  const [newFieldName, setNewFieldName] = useState('')
  const [newExpr, setNewExpr] = useState('')
  const [newRole, setNewRole] = useState('feature')

  // Load initial unified schema
  const initSchema = async () => {
    setLoading(true)
    try {
      const sIds = sources.map((s) => s.source_id)
      const prop = await proposeUnifiedSchema('draft_init', sIds)
      setSchema(prop)
      loadPreview(prop.id)
    } catch (err) {
      console.error('Failed to propose unified schema:', err)
    }
    setLoading(false)
  }

  useEffect(() => {
    initSchema()
  }, [])

  const loadPreview = async (sId) => {
    try {
      const p = await previewUnifiedSchema(sId)
      setPreview(p)
    } catch (err) {
      console.error('Failed to load preview:', err)
    }
  }

  const applyPatch = async (ops) => {
    if (!schema) return
    try {
      const res = await patchUnifiedSchema(schema.id, ops)
      setSchema(res.schema)
      setImpact(res.impact)
      loadPreview(schema.id)
    } catch (err) {
      alert(`Schema edit error: ${err.message}`)
    }
  }

  // Edit actions
  const toggleInclude = (field) => {
    if (field.include) {
      applyPatch([{ op: 'remove_field', params: { field_name: field.field_name, cascade: true } }])
    } else {
      applyPatch([{ op: 'include_field', params: { field_name: field.field_name } }])
    }
  }

  const togglePii = (field) => {
    applyPatch([{ op: 'set_pii', params: { field_name: field.field_name, pii: !field.pii } }])
  }

  const changeRole = (field, role) => {
    applyPatch([{ op: 'set_role', params: { field_name: field.field_name, role } }])
  }

  const handleExcludeAllPii = () => {
    applyPatch([{ op: 'exclude_all_pii', params: {} }])
  }

  const handleUndo = async () => {
    const s = await undoUnifiedSchema(schema.id)
    setSchema(s)
    loadPreview(s.id)
  }

  const handleRedo = async () => {
    const s = await redoUnifiedSchema(schema.id)
    setSchema(s)
    loadPreview(s.id)
  }

  const handleReset = async () => {
    if (confirm('Reset all changes back to the initial AI proposal?')) {
      const s = await resetUnifiedSchema(schema.id)
      setSchema(s)
      loadPreview(s.id)
    }
  }

  const handleShowDiff = async () => {
    const d = await diffUnifiedSchema(schema.id)
    setDiffData(d)
    setActiveModal('diff')
  }

  // Describe in words handler
  const handleDescribeInWords = async () => {
    if (!aiPrompt.trim()) return
    setAiLoading(true)
    try {
      const prop = await deriveFieldFromText(schema.id, aiPrompt)
      setAiProposal(prop)
    } catch (err) {
      alert(`AI Derivation error: ${err.message}`)
    }
    setAiLoading(false)
  }

  const acceptAiProposal = () => {
    if (!aiProposal) return
    applyPatch([
      {
        op: 'add_derived',
        params: {
          field_name: aiProposal.field_name,
          expression: aiProposal.expression,
          role: aiProposal.role,
          description: aiProposal.description,
        },
      },
    ])
    setActiveModal(null)
    setAiProposal(null)
    setAiPrompt('')
  }

  const handleAddManualDerived = () => {
    if (!newFieldName.trim() || !newExpr.trim()) return
    applyPatch([
      {
        op: 'add_derived',
        params: {
          field_name: newFieldName,
          expression: newExpr,
          role: newRole,
        },
      },
    ])
    setActiveModal(null)
    setNewFieldName('')
    setNewExpr('')
  }

  const handleConfirmAndRun = async () => {
    try {
      const sIds = sources.map((s) => s.source_id)
      const res = await createRun(sIds, ['prof_active'])
      onRunComplete(res.run_id)
    } catch (err) {
      alert(`Failed to launch run: ${err.message}`)
    }
  }

  const getProvenanceBadge = (prov) => {
    switch (prov) {
      case 'ai':
        return (
          <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-blue-950/70 text-blue-400 border border-blue-800/50">
            AI
          </span>
        )
      case 'human_added':
        return (
          <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-emerald-950/70 text-emerald-400 border border-emerald-800/50">
            ADDED
          </span>
        )
      case 'human_edited':
        return (
          <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-amber-950/70 text-amber-400 border border-amber-800/50">
            EDITED
          </span>
        )
      case 'human_removed':
        return (
          <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-400 line-through">
            REMOVED
          </span>
        )
      default:
        return null
    }
  }

  if (loading || !schema) {
    return (
      <div className="p-20 text-center text-slate-400 flex flex-col items-center gap-3">
        <Loader2 className="w-8 h-8 animate-spin text-cyan-400" />
        <span className="text-sm">Synthesizing Unified Schema & Join Graph across sources...</span>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full text-xs font-semibold bg-cyan-950/60 text-cyan-400 border border-cyan-800/50 mb-2">
            STEP 3 · UNIFIED SCHEMA REVIEW
          </div>
          <h2 className="text-2xl font-bold text-white tracking-tight">Unified Schema Review & Editor</h2>
          <p className="text-sm text-slate-400">
            The AI proposes how datasets join and map. You have 100% control to promote, derive, or exclude fields.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={onBack}
            className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-900 border border-slate-800 text-slate-300 hover:text-white"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={handleUndo}
            title="Undo"
            className="p-2 rounded-lg text-xs bg-slate-900 border border-slate-800 text-slate-300 hover:text-white"
          >
            <Undo2 className="w-4 h-4" />
          </button>
          <button
            onClick={handleRedo}
            title="Redo"
            className="p-2 rounded-lg text-xs bg-slate-900 border border-slate-800 text-slate-300 hover:text-white"
          >
            <Redo2 className="w-4 h-4" />
          </button>
          <button
            onClick={handleReset}
            title="Reset to AI Proposal"
            className="p-2 rounded-lg text-xs bg-slate-900 border border-slate-800 text-slate-300 hover:text-white"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
          <button
            onClick={handleShowDiff}
            className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-900 border border-slate-800 text-slate-300 hover:text-white flex items-center gap-1.5"
          >
            <GitCompare className="w-3.5 h-3.5 text-cyan-400" />
            Diff vs AI
          </button>
          <button
            onClick={handleExcludeAllPii}
            className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-900 border border-amber-800/60 text-amber-300 hover:bg-slate-800 flex items-center gap-1.5"
          >
            <Shield className="w-3.5 h-3.5" />
            Exclude All PII
          </button>
          <button
            onClick={handleConfirmAndRun}
            className="px-4 py-2 rounded-lg text-xs font-bold bg-cyan-500 hover:bg-cyan-400 text-slate-950 shadow-lg shadow-cyan-500/20 transition-all flex items-center gap-2"
          >
            <Play className="w-4 h-4 fill-current" />
            Confirm & Run
          </button>
        </div>
      </div>

      {/* Main Grid: Left Join Graph | Center Fields Table | Right Impact Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Multi-source Join Graph (3 cols) */}
        <div className="lg:col-span-3 space-y-4">
          <div className="border border-slate-800 rounded-xl p-4 bg-slate-900/40">
            <div className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-3 flex items-center gap-2">
              <GitMerge className="w-4 h-4 text-cyan-400" />
              Proposed Join Graph
            </div>

            {schema.joins.length === 0 ? (
              <div className="text-xs text-slate-500 py-4 text-center">
                Single dataset or no automated identity keys detected.
              </div>
            ) : (
              <div className="space-y-3">
                {schema.joins.map((j) => (
                  <div
                    key={j.id}
                    className="p-3 rounded-lg border border-slate-800 bg-slate-950/60 space-y-2 text-xs"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-white">{j.join_type.toUpperCase()} JOIN</span>
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-cyan-950 text-cyan-300 border border-cyan-800/40">
                        {Math.round(j.match_rate * 100)}% match
                      </span>
                    </div>
                    <div className="text-slate-400 text-[11px] font-mono">
                      <div>L: {j.left_keys.join(', ')}</div>
                      <div>R: {j.right_keys.join(', ')}</div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Center: Unified Fields Table (6 cols) */}
        <div className="lg:col-span-6 space-y-4">
          <div className="border border-slate-800 rounded-xl bg-slate-900/40 overflow-hidden">
            <div className="p-3 bg-slate-900/80 border-b border-slate-800 flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-300">
                Unified Dataset Fields ({schema.fields.filter((f) => f.include).length} active)
              </span>

              {/* + Add Field dropdown */}
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setActiveModal('describe')}
                  className="px-2.5 py-1 rounded text-[11px] font-medium bg-cyan-950/80 text-cyan-300 border border-cyan-800 hover:bg-cyan-900/80 flex items-center gap-1"
                >
                  <Sparkles className="w-3 h-3" />
                  Describe in Words
                </button>
                <button
                  onClick={() => setActiveModal('expression')}
                  className="px-2.5 py-1 rounded text-[11px] font-medium bg-slate-950 border border-slate-700 text-slate-300 hover:text-white flex items-center gap-1"
                >
                  <FileCode2 className="w-3 h-3 text-cyan-400" />
                  DSL Expression
                </button>
              </div>
            </div>

            <div className="overflow-x-auto max-h-[500px]">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 uppercase text-[9px] tracking-wider sticky top-0">
                  <tr>
                    <th className="py-2.5 px-3 w-8">Inc</th>
                    <th className="py-2.5 px-3">Field Name</th>
                    <th className="py-2.5 px-3">Role</th>
                    <th className="py-2.5 px-3">PII</th>
                    <th className="py-2.5 px-3">Origin</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {schema.fields.map((f) => (
                    <tr
                      key={f.field_name}
                      className={`hover:bg-slate-800/30 transition-colors ${
                        !f.include ? 'opacity-40 bg-slate-950/40' : ''
                      }`}
                    >
                      <td className="py-2 px-3">
                        <input
                          type="checkbox"
                          checked={f.include}
                          onChange={() => toggleInclude(f)}
                          className="rounded border-slate-700 bg-slate-950 text-cyan-500 focus:ring-0 cursor-pointer"
                        />
                      </td>
                      <td className="py-2 px-3 font-mono font-medium flex items-center gap-2">
                        <span className={!f.include ? 'line-through text-slate-500' : 'text-white'}>
                          {f.field_name}
                        </span>
                        {getProvenanceBadge(f.provenance)}
                      </td>
                      <td className="py-2 px-3">
                        <select
                          value={f.role}
                          onChange={(e) => changeRole(f, e.target.value)}
                          disabled={!f.include}
                          className="bg-slate-950 border border-slate-700 rounded px-1.5 py-0.5 text-[11px] text-slate-300 focus:outline-none focus:border-cyan-500"
                        >
                          {FIELD_ROLES.map((r) => (
                            <option key={r} value={r}>
                              {r}
                            </option>
                          ))}
                        </select>
                      </td>
                      <td className="py-2 px-3">
                        <button
                          onClick={() => togglePii(f)}
                          disabled={!f.include}
                          className={`px-1.5 py-0.5 rounded text-[10px] font-semibold border ${
                            f.pii
                              ? 'bg-amber-950/70 text-amber-300 border-amber-800'
                              : 'bg-slate-900 text-slate-500 border-slate-800'
                          }`}
                        >
                          {f.pii ? 'PII' : 'Safe'}
                        </button>
                      </td>
                      <td className="py-2 px-3 text-[10px] text-slate-400 font-mono">
                        {f.origin}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Right: Live Impact & Degradation Matrix (3 cols) */}
        <div className="lg:col-span-3 space-y-4">
          <div className="border border-slate-800 rounded-xl p-4 bg-slate-900/40 space-y-3">
            <div className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <Shield className="w-4 h-4 text-cyan-400" />
              Live Detector Impact
            </div>

            <div className="space-y-2">
              {(impact?.degradation_matrix || []).map((d) => (
                <div
                  key={d.feature}
                  className="p-2.5 rounded-lg border border-slate-800 bg-slate-950/50 text-xs space-y-1"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-white">{d.feature}</span>
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                        d.status === 'active'
                          ? 'bg-emerald-950 text-emerald-400'
                          : d.status === 'degraded'
                          ? 'bg-amber-950 text-amber-400'
                          : 'bg-rose-950 text-rose-400'
                      }`}
                    >
                      {d.status}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400">{d.reason}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Describe In Words Modal */}
      {activeModal === 'describe' && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="max-w-lg w-full bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-cyan-400" />
                Describe in Plain English
              </h3>
              <button onClick={() => setActiveModal(null)} className="text-slate-400 hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>
            <p className="text-xs text-slate-400">
              Type the business logic or identity risk rule in natural language. The AI will translate it into
              sandboxed DSL code.
            </p>
            <textarea
              rows={3}
              placeholder="e.g. is the login on a weekend or days since last password change"
              value={aiPrompt}
              onChange={(e) => setAiPrompt(e.target.value)}
              className="w-full p-2.5 text-xs bg-slate-950 border border-slate-700 rounded-md text-white focus:outline-none focus:border-cyan-500"
            />
            <div className="flex justify-end gap-2">
              <button
                onClick={handleDescribeInWords}
                disabled={aiLoading}
                className="px-4 py-1.5 rounded text-xs font-semibold bg-cyan-500 text-slate-950 hover:bg-cyan-400 flex items-center gap-1.5"
              >
                {aiLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : null}
                Generate Expression
              </button>
            </div>

            {aiProposal && (
              <div className="p-3 rounded-lg border border-cyan-800/60 bg-cyan-950/30 space-y-2 text-xs">
                <div className="font-semibold text-cyan-300">
                  Proposed: {aiProposal.field_name}
                </div>
                <code className="block p-2 bg-slate-950 rounded font-mono text-[11px] text-emerald-400">
                  {aiProposal.expression}
                </code>
                <div className="flex justify-end gap-2 pt-2">
                  <button
                    onClick={acceptAiProposal}
                    className="px-3 py-1 rounded text-xs font-semibold bg-emerald-500 text-slate-950 hover:bg-emerald-400"
                  >
                    Accept & Add to Schema
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Manual DSL Modal */}
      {activeModal === 'expression' && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="max-w-md w-full bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <FileCode2 className="w-4 h-4 text-cyan-400" />
                Build DSL Expression
              </h3>
              <button onClick={() => setActiveModal(null)} className="text-slate-400 hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="space-y-3 text-xs">
              <div>
                <label className="text-slate-400 block mb-1">Field Name</label>
                <input
                  type="text"
                  placeholder="e.g. login_ratio"
                  value={newFieldName}
                  onChange={(e) => setNewFieldName(e.target.value)}
                  className="w-full p-2 bg-slate-950 border border-slate-700 rounded text-white"
                />
              </div>
              <div>
                <label className="text-slate-400 block mb-1">DSL Expression</label>
                <input
                  type="text"
                  placeholder="e.g. ratio(${failed_count}, ${login_count})"
                  value={newExpr}
                  onChange={(e) => setNewExpr(e.target.value)}
                  className="w-full p-2 bg-slate-950 border border-slate-700 rounded font-mono text-cyan-300"
                />
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <button
                onClick={handleAddManualDerived}
                className="px-4 py-1.5 rounded text-xs font-semibold bg-cyan-500 text-slate-950 hover:bg-cyan-400"
              >
                Save Field
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Diff Modal */}
      {activeModal === 'diff' && diffData && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="max-w-lg w-full bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4 max-h-[80vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <GitCompare className="w-4 h-4 text-cyan-400" />
                Diff vs AI Proposal
              </h3>
              <button onClick={() => setActiveModal(null)} className="text-slate-400 hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <span className="font-semibold text-emerald-400">Added Fields ({diffData.added_fields?.length || 0}):</span>
                <div className="text-slate-400 font-mono mt-1">
                  {diffData.added_fields?.map((f) => f.field_name).join(', ') || 'None'}
                </div>
              </div>
              <div>
                <span className="font-semibold text-rose-400">Excluded Fields ({diffData.removed_fields?.length || 0}):</span>
                <div className="text-slate-400 font-mono mt-1">
                  {diffData.removed_fields?.map((f) => f.field_name).join(', ') || 'None'}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
