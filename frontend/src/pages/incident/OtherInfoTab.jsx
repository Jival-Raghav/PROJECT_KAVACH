import { ActorTable } from '../Actors'
import { ControlTable } from '../ControlFindings'

function Block({ title, help, count, empty, children }) {
  return (
    <section className="card kc-block">
      <header className="kc-block-head">
        <h4>{title}</h4>
        <span className="kc-count">{count}</span>
      </header>
      {help && <p className="kc-muted">{help}</p>}
      {count > 0 ? children : <p className="kc-muted">{empty}</p>}
    </section>
  )
}

export default function OtherInfoTab({ inc }) {
  const response = inc.response || []
  const controls = inc.compliance || []
  const actors = inc.actors || []
  const anomaly = inc.anomaly || []
  return (
    <div className="kc-tab-page">
      <div className="kc-tab-intro">
        <h3>Other info</h3>
        <p>What to do next, plus supporting context from the rest of the analysis.</p>
      </div>

      <Block title="What to do" count={response.length} help="Proposed actions only. Approve them on the Response Plan page; Kavach never changes the firewall."
        empty="No actions proposed for this incident.">
        <ul className="kc-actions-list">
          {response.map(a => (
            <li key={a.action_id}><b>{a.title}</b><span className="kc-muted">{a.why}</span></li>
          ))}
        </ul>
      </Block>

      <Block title="Controls" count={controls.length} help="Security controls this incident shows failing or being tested. The standards mapping is ours and is not an audit."
        empty="No controls linked to this incident.">
        <div className="kc-scroll-x"><ControlTable controls={controls} /></div>
      </Block>

      <Block title="Unusual behaviour" count={anomaly.length} help="Context only: anomaly scores do not change this incident's risk score."
        empty="Nothing unusual recorded for the entities in this incident.">
        <div className="kc-scroll-x">
          <table className="kc-table static compact">
            <thead><tr><th>Entity</th><th>Score</th><th>Why it stands out</th></tr></thead>
            <tbody>
              {anomaly.map(a => (
                <tr key={`${a.kind}:${a.entity}`}>
                  <td className="mono">{a.entity}</td>
                  <td className="mono">{a.score.toFixed(1)}</td>
                  <td>{a.reasons.map(r => <div key={r}>{r}</div>)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Block>

      <Block title="Linked actors" count={actors.length} help="IPs and accounts tied together by successful logins, configuration changes or account creation."
        empty="No linked actors for this incident.">
        <div className="kc-scroll-x"><ActorTable actors={actors} /></div>
      </Block>
    </div>
  )
}
