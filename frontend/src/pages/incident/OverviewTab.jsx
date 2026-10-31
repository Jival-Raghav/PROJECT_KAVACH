import { ChevronRight } from 'lucide-react'
import { STAGES } from '../KillChain'
import { OUTCOME, fmtDuration, fmtTime } from './format'

export default function OverviewTab({ inc, tabs, onOpen }) {
  const got = inc.timeline.filter(s => s.outcome !== 'blocked').length
  const v = inc.review?.verdict
  return (
    <div className="kc-tab-page">
      <section className="card kc-block">
        <h4>How far the attack got</h4>
        <ol className="kc-chain">
          {STAGES.map(s => <li key={s} className={inc.stages.includes(s) ? 'on' : ''}>{s}</li>)}
        </ol>
      </section>

      <div className="kc-stat-row">
        <div className="kc-stat"><b>{Math.round(inc.risk_score)}</b><span>Risk score out of 100</span></div>
        <div className="kc-stat"><b>{got} of {inc.timeline.length}</b><span>Steps that got through</span></div>
        <div className="kc-stat"><b>{inc.raw_alert_count.toLocaleString()}</b><span>Raw alerts merged</span></div>
        <div className="kc-stat"><b>{fmtDuration(inc.first_seen, inc.last_seen) || '-'}</b><span>Duration</span></div>
        <div className="kc-stat"><b>{inc.reach.targets.length.toLocaleString()}</b><span>Targets in range</span></div>
      </div>

      <section className="card kc-block">
        <h4>What happened</h4>
        <ol className="kc-overview-steps">
          {inc.timeline.map((s, i) => (
            <li key={s.detection_id}>
              <span className="kc-step-no">{i + 1}</span>
              <div><b>{s.technique_name}</b><div className="kc-muted">{fmtTime(s.ts)} · {s.stage}</div></div>
              <span className={`kc-outcome tone-${OUTCOME[s.outcome]?.tone || 'plain'}`}>{OUTCOME[s.outcome]?.label || s.outcome}</span>
            </li>
          ))}
        </ol>
        {v && <p className="kc-overview-verdict"><b>Verdict: {v.final_priority} priority.</b> {v.reason}</p>}
      </section>

      <div className="kc-nav-cards">
        {tabs.filter(t => t.id !== 'overview').map(({ id, label, icon: Icon, blurb }) => (
          <button key={id} className="card kc-nav-card" onClick={() => onOpen(id)}>
            <Icon size={18} />
            <span><b>{label}</b><small>{blurb}</small></span>
            <ChevronRight size={15} />
          </button>
        ))}
      </div>
    </div>
  )
}
