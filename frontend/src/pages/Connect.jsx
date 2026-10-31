import React, { useState } from 'react'
import { Upload, Database, FileSpreadsheet, CheckCircle2, ArrowRight, Loader2, AlertCircle } from 'lucide-react'
import { uploadSourceFile, registerSqlSource } from '../api'

export default function Connect({ onNext, sources, setSources }) {
  const [uploading, setUploading] = useState(false)
  const [error, setError] = useState(null)
  const [sqlMode, setSqlMode] = useState(false)
  const [sqlConfig, setSqlConfig] = useState({
    connection_string: '',
    table_name: '',
    query: '',
  })

  const handleFileUpload = async (e) => {
    const files = Array.from(e.target.files || [])
    if (!files.length) return

    setUploading(true)
    setError(null)
    const newSources = [...sources]

    for (const file of files) {
      try {
        const resp = await uploadSourceFile(file)
        newSources.push(resp)
      } catch (err) {
        setError(`Failed to upload ${file.name}: ${err.message}`)
      }
    }

    setSources(newSources)
    setUploading(false)
  }

  const handleSqlConnect = async (e) => {
    e.preventDefault()
    if (!sqlConfig.connection_string) {
      setError('Connection string is required.')
      return
    }
    setUploading(true)
    setError(null)
    try {
      const resp = await registerSqlSource(sqlConfig)
      setSources([...sources, resp])
      setSqlMode(false)
    } catch (err) {
      setError(`SQL connection failed: ${err.message}`)
    }
    setUploading(false)
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full text-xs font-semibold bg-cyan-950/60 text-cyan-400 border border-cyan-800/50 mb-2">
            STEP 1 · INGESTION
          </div>
          <h2 className="text-2xl font-bold text-white tracking-tight">Connect Data Sources</h2>
          <p className="text-sm text-slate-400">
            Ingest identity, activity, and entitlement datasets across any enterprise format.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setSqlMode(!sqlMode)}
            className="px-3.5 py-2 rounded-lg text-xs font-medium bg-slate-900 border border-slate-700 text-slate-300 hover:text-white hover:border-slate-600 transition-colors flex items-center gap-2"
          >
            <Database className="w-4 h-4 text-cyan-400" />
            {sqlMode ? 'Switch to File Upload' : 'Connect SQL Database'}
          </button>
          <button
            disabled={sources.length === 0}
            onClick={onNext}
            className={`px-4 py-2 rounded-lg text-xs font-semibold flex items-center gap-2 transition-all ${
              sources.length > 0
                ? 'bg-cyan-500 hover:bg-cyan-400 text-onaccent shadow-lg shadow-cyan-500/20 cursor-pointer'
                : 'bg-slate-800 text-slate-500 cursor-not-allowed'
            }`}
          >
            Configure Mappings
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3.5 rounded-lg bg-red-950/50 border border-red-800/60 text-red-300 text-sm flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
          {error}
        </div>
      )}

      {/* Upload Drop Zone / SQL Config */}
      {!sqlMode ? (
        <label className="relative border-2 border-dashed border-slate-700 hover:border-cyan-500/60 rounded-xl p-8 flex flex-col items-center justify-center gap-3 cursor-pointer bg-slate-900/40 hover:bg-slate-900/70 transition-all group">
          <input
            type="file"
            multiple
            accept=".csv,.tsv,.json,.jsonl,.parquet"
            onChange={handleFileUpload}
            className="sr-only"
            disabled={uploading}
          />
          <div className="w-12 h-12 rounded-full bg-slate-800 flex items-center justify-center text-cyan-400 group-hover:scale-110 transition-transform shadow-inner">
            {uploading ? <Loader2 className="w-6 h-6 animate-spin" /> : <Upload className="w-6 h-6" />}
          </div>
          <div className="text-center">
            <span className="text-sm font-semibold text-white group-hover:text-cyan-300">
              {uploading ? 'Processing & Profiling Datasets...' : 'Drop files here or browse'}
            </span>
            <p className="text-xs text-slate-400 mt-1">
              Supports CSV, TSV, Nested JSON/JSONL, and Parquet. Automatic schema profiling.
            </p>
          </div>
        </label>
      ) : (
        <form onSubmit={handleSqlConnect} className="p-5 rounded-xl border border-slate-800 bg-slate-900/60 space-y-4">
          <div className="text-sm font-semibold text-white flex items-center gap-2">
            <Database className="w-4 h-4 text-cyan-400" />
            Read-Only SQL Connection
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-slate-400 block mb-1">SQLAlchemy Connection URI</label>
              <input
                type="text"
                placeholder="postgresql://user:pass@host:5432/db or sqlite:///data.db"
                value={sqlConfig.connection_string}
                onChange={(e) => setSqlConfig({ ...sqlConfig, connection_string: e.target.value })}
                className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-700 rounded-md text-white focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div>
              <label className="text-xs text-slate-400 block mb-1">Table Name</label>
              <input
                type="text"
                placeholder="e.g. audit_events or hr_users"
                value={sqlConfig.table_name}
                onChange={(e) => setSqlConfig({ ...sqlConfig, table_name: e.target.value })}
                className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-700 rounded-md text-white focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={() => setSqlMode(false)}
              className="px-3 py-1.5 rounded text-xs text-slate-400 hover:text-white"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={uploading}
              className="px-4 py-1.5 rounded text-xs font-semibold bg-cyan-500 text-onaccent hover:bg-cyan-400"
            >
              Connect & Profile
            </button>
          </div>
        </form>
      )}

      {/* Connected Datasets Roster */}
      <div className="space-y-3">
        <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
          Connected Sources ({sources.length})
        </div>

        {sources.length === 0 ? (
          <div className="p-6 text-center border border-slate-800 rounded-xl bg-slate-900/20 text-slate-500 text-xs">
            No datasets uploaded yet. Upload your event logs, HR files, or entitlements above to begin.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {sources.map((src, i) => (
              <div
                key={src.source_id || i}
                className="p-4 rounded-xl border border-slate-800 bg-slate-900/50 hover:border-slate-700 transition-colors flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <FileSpreadsheet className="w-4 h-4 text-cyan-400" />
                      <span className="text-sm font-medium text-white truncate max-w-[200px]">
                        {src.filename}
                      </span>
                    </div>
                    <span className="px-2 py-0.5 rounded text-[11px] font-mono uppercase bg-slate-800 text-slate-300 border border-slate-700">
                      {src.file_type}
                    </span>
                  </div>
                  <div className="text-xs text-slate-400 flex items-center gap-4 mt-2">
                    <span>{src.row_count.toLocaleString()} rows</span>
                    <span>·</span>
                    <span>{src.profile?.columns?.length || 0} columns</span>
                  </div>
                </div>

                <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between">
                  <div className="flex items-center gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
                    <span className="text-xs text-slate-300">
                      Role:{' '}
                      <strong className="text-cyan-300 font-semibold">{src.suggested_role}</strong>
                    </span>
                  </div>
                  <span className="text-[11px] text-slate-400">
                    {Math.round((src.role_confidence || 0.9) * 100)}% match
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
