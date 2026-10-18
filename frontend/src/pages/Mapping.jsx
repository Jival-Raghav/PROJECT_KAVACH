import React, { useState, useEffect } from 'react'
import { Sparkles, Check, AlertTriangle, ArrowRight, Eye, RefreshCw, Loader2, ArrowLeft } from 'lucide-react'
import { proposeSourceMapping, saveMappingProfile, previewMapping } from '../api'

const AVAILABLE_TRANSFORMS = [
  { op: 'identity', label: 'As Is (Identity)' },
  { op: 'lower', label: 'Lowercase' },
  { op: 'upper', label: 'Uppercase' },
  { op: 'strip', label: 'Trim Whitespace' },
  { op: 'parse_datetime', label: 'Parse Datetime (UTC)' },
  { op: 'epoch_s', label: 'Epoch Seconds' },
  { op: 'epoch_ms', label: 'Epoch Milliseconds' },
  { op: 'bool_map', label: 'Boolean Map' },
  { op: 'domain_strip', label: 'Strip Domain (User/Email)' },
  { op: 'arn_user', label: 'Extract AWS ARN User' },
]

export default function Mapping({ onBack, onNext, sources }) {
  const [activeSourceIndex, setActiveSourceIndex] = useState(0)
  const [loading, setLoading] = useState(false)
  const [mappingsBySource, setMappingsBySource] = useState({})
  const [previewData, setPreviewData] = useState(null)
  const [previewLoading, setPreviewLoading] = useState(false)

  const currentSource = sources[activeSourceIndex]

  // Propose mapping when selecting a source
  const loadProposal = async (source) => {
    if (!source) return
    const sId = source.source_id
    if (mappingsBySource[sId]) return

    setLoading(true)
    try {
      const resp = await proposeSourceMapping(sId, source.suggested_role, true)
      setMappingsBySource((prev) => ({
        ...prev,
        [sId]: resp.mappings || [],
      }))
    } catch (err) {
      console.error('Mapping proposal failed:', err)
    }
    setLoading(false)
  }

  useEffect(() => {
    if (currentSource) {
      loadProposal(currentSource)
    }
  }, [currentSource])

  const currentMappings = currentSource ? mappingsBySource[currentSource.source_id] || [] : []

  const updateMapping = (idx, field, value) => {
    const sId = currentSource.source_id
    const updated = [...currentMappings]
    if (field === 'transform_op') {
      updated[idx] = {
        ...updated[idx],
        transform: { op: value, args: {} },
      }
    } else {
      updated[idx] = { ...updated[idx], [field]: value }
    }
    setMappingsBySource({ ...mappingsBySource, [sId]: updated })
  }

  const handlePreview = async () => {
    if (!currentSource) return
    setPreviewLoading(true)
    try {
      const resp = await previewMapping(currentSource.source_id, {
        source_id: currentSource.source_id,
        role: currentSource.suggested_role,
        mappings: currentMappings,
      })
      setPreviewData(resp)
    } catch (err) {
      console.error('Preview error:', err)
    }
    setPreviewLoading(false)
  }

  const handleSaveAndContinue = async () => {
    // Save profile for each source
    for (const src of sources) {
      const maps = mappingsBySource[src.source_id] || []
      try {
        await saveMappingProfile(`prof_${src.source_id}`, {
          source_id: src.source_id,
          role: src.suggested_role,
          mappings: maps,
        })
      } catch (err) {
        console.error('Save mapping profile error:', err)
      }
    }
    onNext()
  }

  const getConfidenceBadge = (conf) => {
    if (conf >= 0.85) {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-950/60 text-emerald-400 border border-emerald-800/50">
          <Check className="w-3 h-3" />
          {Math.round(conf * 100)}%
        </span>
      )
    } else if (conf >= 0.6) {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-950/60 text-amber-400 border border-amber-800/50">
          <AlertTriangle className="w-3 h-3" />
          {Math.round(conf * 100)}%
        </span>
      )
    }
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold bg-rose-950/60 text-rose-400 border border-rose-800/50">
        Review ({Math.round(conf * 100)}%)
      </span>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full text-xs font-semibold bg-cyan-950/60 text-cyan-400 border border-cyan-800/50 mb-2">
            STEP 2 · SCHEMA AUTOPILOT
          </div>
          <h2 className="text-2xl font-bold text-white tracking-tight">Canonical Column Mapping</h2>
          <p className="text-sm text-slate-400">
            Verify AI-proposed transformations from raw columns into canonical models.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={onBack}
            className="px-3.5 py-2 rounded-lg text-xs font-medium bg-slate-900 border border-slate-800 text-slate-300 hover:text-white transition-colors flex items-center gap-1.5"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            Back
          </button>
          <button
            onClick={handlePreview}
            disabled={previewLoading}
            className="px-3.5 py-2 rounded-lg text-xs font-medium bg-slate-900 border border-cyan-800/60 text-cyan-400 hover:bg-slate-800 transition-colors flex items-center gap-1.5"
          >
            {previewLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Eye className="w-3.5 h-3.5" />}
            Preview 20 Rows
          </button>
          <button
            onClick={handleSaveAndContinue}
            className="px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-500 hover:bg-cyan-400 text-onaccent shadow-lg shadow-cyan-500/20 transition-all flex items-center gap-2"
          >
            Review Unified Schema
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Source Selector Tabs */}
      {sources.length > 1 && (
        <div className="flex gap-2 border-b border-slate-800 pb-2">
          {sources.map((src, i) => (
            <button
              key={src.source_id}
              onClick={() => setActiveSourceIndex(i)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                i === activeSourceIndex
                  ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-800'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {src.filename} ({src.suggested_role})
            </button>
          ))}
        </div>
      )}

      {/* Mapping Table */}
      <div className="border border-slate-800 rounded-xl overflow-hidden bg-slate-900/40">
        <div className="p-3.5 bg-slate-900/80 border-b border-slate-800 flex items-center justify-between">
          <div className="text-xs font-semibold text-slate-300 flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-cyan-400" />
            {currentSource?.filename} — Active Mappings
          </div>
          <button
            onClick={() => loadProposal(currentSource)}
            className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
          >
            <RefreshCw className="w-3 h-3" /> Re-run Autopilot
          </button>
        </div>

        {loading ? (
          <div className="p-12 text-center text-slate-400 flex flex-col items-center gap-3">
            <Loader2 className="w-6 h-6 animate-spin text-cyan-400" />
            <span className="text-xs">Analyzing semantic profiles and matching canonical entities...</span>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/60 text-slate-400 border-b border-slate-800 uppercase tracking-wider text-[10px]">
                <tr>
                  <th className="py-2.5 px-4 font-semibold">Canonical Target</th>
                  <th className="py-2.5 px-4 font-semibold">Source Column</th>
                  <th className="py-2.5 px-4 font-semibold">Declarative Transform</th>
                  <th className="py-2.5 px-4 font-semibold">Confidence</th>
                  <th className="py-2.5 px-4 font-semibold">Rationale</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {currentMappings.map((m, idx) => (
                  <tr key={m.canonical_field} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 px-4 font-mono font-medium text-cyan-300">
                      {m.canonical_field}
                    </td>
                    <td className="py-3 px-4">
                      <select
                        value={m.source_column}
                        onChange={(e) => updateMapping(idx, 'source_column', e.target.value)}
                        className="bg-slate-950 border border-slate-700 rounded px-2.5 py-1 text-xs text-white focus:outline-none focus:border-cyan-500"
                      >
                        {currentSource?.profile?.columns?.map((col) => (
                          <option key={col.name} value={col.name}>
                            {col.name} ({col.semantic_type})
                          </option>
                        ))}
                      </select>
                    </td>
                    <td className="py-3 px-4">
                      <select
                        value={m.transform?.op || 'identity'}
                        onChange={(e) => updateMapping(idx, 'transform_op', e.target.value)}
                        className="bg-slate-950 border border-slate-700 rounded px-2.5 py-1 text-xs text-white focus:outline-none focus:border-cyan-500"
                      >
                        {AVAILABLE_TRANSFORMS.map((tf) => (
                          <option key={tf.op} value={tf.op}>
                            {tf.label}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td className="py-3 px-4">{getConfidenceBadge(m.confidence)}</td>
                    <td className="py-3 px-4 text-slate-400 text-[11px] truncate max-w-xs">
                      {m.rationale}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Live Preview Modal / Section */}
      {previewData && (
        <div className="border border-slate-800 rounded-xl p-4 bg-slate-900/60 space-y-3">
          <div className="text-xs font-semibold text-white flex items-center justify-between">
            <span className="flex items-center gap-1.5">
              <Eye className="w-3.5 h-3.5 text-cyan-400" />
              Transformed Sample Rows (First 20)
            </span>
            <span className="text-[11px] text-emerald-400">
              {previewData.validation?.can_run ? '✓ Valid canonical format' : '⚠ Validation issues'}
            </span>
          </div>

          <div className="overflow-x-auto max-h-64 border border-slate-800 rounded">
            <table className="w-full text-left text-[11px] text-slate-300">
              <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 uppercase text-[9px]">
                <tr>
                  {Object.keys(previewData.preview_rows[0] || {}).map((k) => (
                    <th key={k} className="p-2 font-mono">
                      {k}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/40">
                {previewData.preview_rows.map((row, i) => (
                  <tr key={i} className="hover:bg-slate-800/20 font-mono">
                    {Object.values(row).map((v, cIdx) => (
                      <td key={cIdx} className="p-2 truncate max-w-xs">
                        {String(v ?? '')}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
