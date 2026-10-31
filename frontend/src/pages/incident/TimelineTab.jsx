import { OUTCOME, fmtDuration, fmtTime, prettifyText } from './format'

const humanize = key => key.replace(/_/g, ' ').replace(/^./, c => c.toUpperCase())

function Step({ step, no, detection, previous }) {
  const outcome = OUTCOME[step.outcome]
  const gap = previous ? fmtDuration(previous.ts, step.ts) : ''
  const entities = Object.entries(detection?.entities || {})
  return (
    <>
      {gap && <div className="kc-tl-gap">{gap} later</div>}
      <li className={`kc-tl-step tone-${outcome?.tone || 'plain'}`}>
        <span className="kc-tl-marker">{no}</span>
        <article className="card kc-tl-card">
          <header>
            <div>
              <h4>{step.technique_name}</h4>
              <div className="kc-muted">{fmtTime(step.ts)}</div>
            </div>
            {outcome && <span className={`kc-outcome tone-${outcome.tone}`} title={outcome.help}>{outcome.label}</span>}
          </header>
          <p>{prettifyText(step.description)}</p>
          <div className="kc-tl-facts">
            <div><span>Kill-chain stage</span><b>{step.stage}</b></div>
            <div><span>ATT&amp;CK tactic</span><b>{humanize(step.tactic)}</b></div>
            <div><span>Technique</span><b className="mono">{step.technique_id}</b></div>
            <div><span>Events</span><b>{step.event_count.toLocaleString()}</b></div>
            {detection && <div><span>Lasted</span><b>{fmtDuration(detection.first_seen, detection.last_seen) || '-'}</b></div>}
          </div>
          {detection && (
            <details className="kc-tl-more">
              <summary>Show evidence</summary>
              <div className="kc-kv"><span>Detection rule</span><b className="mono">{detection.rule_id}</b></div>
              {entities.map(([role, values]) => (
                <div className="kc-kv" key={role}>
                  <span>{humanize(role)}</span>
                  <b className="mono">{values.join(', ')}</b>
                </div>
              ))}
              <div className="kc-kv">
                <span>First log lines</span>
                <b className="mono">{detection.sample_line_nos.slice(0, 5).map(n => n.toLocaleString()).join(', ')}</b>
              </div>
            </details>
          )}
        </article>
      </li>
    </>
  )
}

export default function TimelineTab({ inc }) {
  const details = new Map(inc.detections.map(d => [d.detection_id, d]))
  const counts = Object.keys(OUTCOME)
    .map(k => [OUTCOME[k], inc.timeline.filter(s => s.outcome === k).length])
    .filter(([, n]) => n > 0)
  return (
    <div className="kc-tab-page">
      <div className="kc-tab-intro">
        <h3>Timeline</h3>
        <p>
          {inc.timeline.length} {inc.timeline.length === 1 ? 'step' : 'steps'} over{' '}
          {fmtDuration(inc.first_seen, inc.last_seen) || 'under a second'}, from {fmtTime(inc.first_seen)} to{' '}
          {fmtTime(inc.last_seen)}, on the firewall's clock.
        </p>
        <div className="kc-tl-counts">
          {counts.map(([o, n]) => <span key={o.label} className={`kc-outcome tone-${o.tone}`} title={o.help}>{n} {o.label.toLowerCase()}</span>)}
        </div>
      </div>
      <ol className="kc-tl">
        {inc.timeline.map((s, i) => (
          <Step key={s.detection_id} step={s} no={i + 1} detection={details.get(s.detection_id)}
            previous={inc.timeline[i - 1]} />
        ))}
      </ol>
    </div>
  )
}
