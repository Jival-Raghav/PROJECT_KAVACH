import { useEffect, useState } from 'react'
import { ChevronLeft, ChevronRight } from 'lucide-react'
import { getAnomalies } from '../api'

const PAGE_SIZE = 50
const KIND_LABEL = { internal_host: 'Internal host', external_ip: 'External IP', user: 'User' }

export default function Anomalies() {
  const [data, setData] = useState({ total: 0, items: [] })
  const [offset, setOffset] = useState(0)
  const [error, setError] = useState('')

  useEffect(() => {
    getAnomalies(PAGE_SIZE, offset).then(setData).catch(e => setError(String(e)))
  }, [offset])

  const last = Math.min(offset + PAGE_SIZE, data.total)

  return (
    <div className="kc-page">
      <div className="card kc-note">
        Internal hosts and users scoring above 50, and external IPs above 80, that are in no
        incident, highest first. These are leads to look at, not confirmed attacks, and they never
        appear on the incident board.
      </div>
      {error && <div className="kc-error">{error}</div>}
      <div className="card kc-table-wrap">
        <table className="kc-table static">
          <thead><tr><th>Score</th><th>Entity</th><th>Type</th><th>Why it is unusual</th></tr></thead>
          <tbody>
            {data.items.map(a => (
              <tr key={`${a.kind}:${a.entity}`}>
                <td className="mono">{a.score.toFixed(1)}</td>
                <td className="mono">{a.entity}</td>
                <td>{KIND_LABEL[a.kind] || a.kind}</td>
                <td>{a.reasons.map(r => <div key={r}>{r}</div>)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="kc-actions">
        <span className="kc-muted">
          {data.total ? `${(offset + 1).toLocaleString()}–${last.toLocaleString()} of ${data.total.toLocaleString()}` : 'No anomaly leads'}
        </span>
        <button className="btn-ghost" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>
          <ChevronLeft size={13} /> Previous
        </button>
        <button className="btn-ghost" disabled={last >= data.total} onClick={() => setOffset(offset + PAGE_SIZE)}>
          Next <ChevronRight size={13} />
        </button>
      </div>
    </div>
  )
}
