import { useState } from 'react'
import { AlertTriangle, Loader2, Play } from 'lucide-react'
import { startLive } from '../../api'
import { useRun } from '../../run'

export default function StartLive({ onStarted }) {
  const { refreshRuns, selectRun } = useRun()
  const [path, setPath] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const submit = async e => {
    e.preventDefault()
    if (!path.trim() || busy) return
    setBusy(true)
    setError('')
    try {
      const { run_id } = await startLive(path.trim())
      await refreshRuns()
      selectRun(run_id)
      onStarted?.()
    } catch (err) {
      setError(typeof err.detail === 'string' ? err.detail : err.message)
      setBusy(false)
    }
  }

  return (
    <form className="card live-start" onSubmit={submit}>
      <label className="live-start-label" htmlFor="live-path">Log file on this computer</label>
      <div className="live-start-row">
        <input
          id="live-path"
          className="live-start-input mono"
          value={path}
          onChange={e => setPath(e.target.value)}
          placeholder="/path/to/firewall.log"
          autoComplete="off"
          spellCheck={false}
        />
        <button className="btn-primary" type="submit" disabled={busy || !path.trim()}>
          {busy ? <Loader2 size={13} className="spin-slow" /> : <Play size={13} />} Start live analysis
        </button>
      </div>
      <p className="kc-muted live-start-note">
        FortiGate key=value log, plain or .gz. Results appear within about a minute and keep
        updating until the whole file is processed.
      </p>
      {error && <div className="kc-error"><AlertTriangle size={14} /> {error}</div>}
    </form>
  )
}
