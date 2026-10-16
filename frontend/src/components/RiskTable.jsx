import { useState, useMemo } from 'react'
import { ChevronDown, ChevronUp, Search, SlidersHorizontal, Shield, User } from 'lucide-react'

/* ── Helpers ──────────────────────────────────────────── */

function riskBarColor(score) {
  if (score >= 70) return 'var(--c-critical)'
  if (score >= 50) return 'var(--c-review)'
  if (score >= 30) return 'var(--c-review)'
  return 'var(--c-normal)'
}

function RiskBadge({ score }) {
  if (score >= 70) return <span className="badge-critical">HIGH {score.toFixed(0)}</span>
  if (score >= 50) return <span className="badge-review">REVIEW {score.toFixed(0)}</span>
  if (score >= 25) return <span className="badge-neutral">LOW {score.toFixed(0)}</span>
  return <span className="badge-normal">OK {score.toFixed(0)}</span>
}

function FlagTag({ flag }) {
  const isAmber = ['AFTER_HOURS_ADMIN_OP', 'BULK_EXPORT', 'CROSS_DEPT_ACCESS'].includes(flag)
  const cls = isAmber ? 'flag-tag amber' : 'flag-tag'
  return <span className={cls}>{flag.replace(/_/g, ' ')}</span>
}

const PRIVILEGE_ICON = { admin: '🔴', 'power-user': '🟠', user: '🟢', service: '🔵' }

/* ── Component ─────────────────────────────────────────── */

export default function RiskTable({ users, onSelectUser, selectedUser }) {
  const [search,       setSearch]       = useState('')
  const [filterDept,   setFilterDept]   = useState('all')
  const [filterPriv,   setFilterPriv]   = useState('all')
  const [sortKey,      setSortKey]      = useState('risk_score')
  const [sortDir,      setSortDir]      = useState('desc')
  const [showFilters,  setShowFilters]  = useState(false)

  const depts = useMemo(() => ['all', ...new Set(users.map(u => u.department))], [users])
  const privs = useMemo(() => ['all', ...new Set(users.map(u => u.privilege_level))], [users])

  const visible = useMemo(() => {
    let list = users.filter(u => {
      const q = search.toLowerCase()
      if (q && !u.username?.toLowerCase().includes(q) && !u.user_id?.toLowerCase().includes(q) && !u.department?.toLowerCase().includes(q)) return false
      if (filterDept !== 'all' && u.department !== filterDept) return false
      if (filterPriv !== 'all' && u.privilege_level !== filterPriv) return false
      return true
    })
    list = [...list].sort((a, b) => {
      let av = a[sortKey] ?? 0, bv = b[sortKey] ?? 0
      if (typeof av === 'string') av = av.toLowerCase()
      if (typeof bv === 'string') bv = bv.toLowerCase()
      return sortDir === 'asc' ? (av > bv ? 1 : -1) : (av < bv ? 1 : -1)
    })
    return list
  }, [users, search, filterDept, filterPriv, sortKey, sortDir])

  const toggleSort = key => {
    if (sortKey === key) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortKey(key); setSortDir('desc') }
  }

  const SortIcon = ({ k }) => sortKey === k
    ? (sortDir === 'asc' ? <ChevronUp size={11} /> : <ChevronDown size={11} />)
    : <ChevronDown size={11} style={{ opacity: 0.2 }} />

  const COLS = [
    { key: 'username',       label: 'User'       },
    { key: 'department',     label: 'Dept'       },
    { key: 'privilege_level',label: 'Priv'       },
    { key: 'risk_score',     label: 'Risk Score' },
    { key: null,             label: 'Flags'      },
    { key: null,             label: ''           },
  ]

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10, height: '100%' }}>

      {/* ── Toolbar ── */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <div style={{ position: 'relative', flex: 1, minWidth: 180 }}>
          <Search size={13} style={{ position: 'absolute', left: 9, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
          <input
            id="risk-search"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search user, ID, department…"
            className="sg-input"
          />
        </div>

        <button
          onClick={() => setShowFilters(f => !f)}
          style={{
            display: 'flex', alignItems: 'center', gap: 6, padding: '5px 12px',
            borderRadius: 3, border: `1px solid ${showFilters ? 'var(--sg-red-border)' : 'var(--border)'}`,
            background: showFilters ? 'var(--sg-red-subtle)' : 'var(--surface-mid)',
            color: showFilters ? 'var(--sg-red)' : 'var(--text-secondary)',
            fontSize: 12, cursor: 'pointer', transition: 'all 150ms ease',
          }}
        >
          <SlidersHorizontal size={13} /> Filters
        </button>

        {showFilters && (
          <>
            <select value={filterDept} onChange={e => setFilterDept(e.target.value)} className="sg-select">
              {depts.map(d => <option key={d} value={d}>{d === 'all' ? 'All Departments' : d}</option>)}
            </select>
            <select value={filterPriv} onChange={e => setFilterPriv(e.target.value)} className="sg-select">
              {privs.map(p => <option key={p} value={p}>{p === 'all' ? 'All Privileges' : p}</option>)}
            </select>
          </>
        )}

        <span style={{ fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap', marginLeft: 'auto' }}>
          {visible.length} / {users.length} users
        </span>
      </div>

      {/* ── Table ── */}
      <div style={{ flex: 1, minHeight: 0, overflowX: 'auto', overflowY: 'auto', borderRadius: 4, border: '1px solid var(--border)' }}>
        <table className="sg-table">
          <thead>
            <tr>
              {COLS.map(({ key, label }, i) => (
                <th
                  key={i}
                  className={`sg-th${key ? ' sortable' : ''}`}
                  onClick={() => key && toggleSort(key)}
                >
                  <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                    {label}{key && <SortIcon k={key} />}
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {visible.map(user => {
              const isSelected = selectedUser?.user_id === user.user_id
              const flags = user.flags || []
              return (
                <tr
                  key={user.user_id}
                  className={`sg-tr${isSelected ? ' selected' : ''}${user.suppressed ? ' suppressed' : ''}`}
                  onClick={() => onSelectUser(user)}
                >
                  {/* User */}
                  <td className="sg-td">
                    <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
                      <div style={{
                        width: 28, height: 28, borderRadius: '50%', flexShrink: 0,
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        background: user.privilege_level === 'admin' ? 'var(--c-critical-bg)' : 'var(--surface-high)',
                        color: user.privilege_level === 'admin' ? 'var(--c-critical)' : 'var(--text-secondary)',
                        fontSize: 11, fontWeight: 700,
                      }}>
                        {user.username?.[0]?.toUpperCase() || '?'}
                      </div>
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <span style={{ fontWeight: 500, color: 'var(--text-primary)', fontSize: 13 }}>{user.username}</span>
                          {user.suppressed && <span className="badge-neutral">Suppressed</span>}
                        </div>
                        <div className="mono" style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 1 }}>{user.user_id}</div>
                      </div>
                    </div>
                  </td>

                  {/* Dept */}
                  <td className="sg-td" style={{ fontSize: 12 }}>{user.department}</td>

                  {/* Priv */}
                  <td className="sg-td">
                    <span style={{ fontSize: 12 }}>{PRIVILEGE_ICON[user.privilege_level] || '⚪'} {user.privilege_level}</span>
                  </td>

                  {/* Risk Score */}
                  <td className="sg-td">
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <div style={{ width: 64 }}>
                        <div className="risk-bar">
                          <div
                            className="risk-bar-fill"
                            style={{ width: `${user.risk_score}%`, background: riskBarColor(user.risk_score) }}
                          />
                        </div>
                      </div>
                      <RiskBadge score={Number(user.risk_score)} />
                    </div>
                  </td>

                  {/* Flags */}
                  <td className="sg-td">
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                      {flags.slice(0, 2).map(f => <FlagTag key={f} flag={f} />)}
                      {flags.length > 2 && (
                        <span className="badge-neutral">+{flags.length - 2}</span>
                      )}
                    </div>
                  </td>

                  {/* Action */}
                  <td className="sg-td">
                    <button
                      id={`inspect-${user.user_id}`}
                      onClick={e => { e.stopPropagation(); onSelectUser(user) }}
                      className="btn-ghost"
                    >
                      Inspect
                    </button>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>

        {visible.length === 0 && (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 120, color: 'var(--text-muted)', fontSize: 13 }}>
            No users match your filters.
          </div>
        )}
      </div>
    </div>
  )
}
