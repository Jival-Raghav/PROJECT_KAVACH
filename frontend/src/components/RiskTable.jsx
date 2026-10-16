import { useState, useMemo } from 'react'
import { ChevronDown, ChevronUp, Search, SlidersHorizontal, Shield, User } from 'lucide-react'

const FLAG_COLORS = {
  STALE_PRIVILEGED_ACCOUNT:   'text-rose-300 border-rose-400/40',
  VERY_STALE_ACCOUNT:         'text-rose-400 border-rose-500/40',
  INACTIVE_ADMIN:             'text-rose-300 border-rose-400/40',
  AFTER_HOURS_ADMIN_OP:       'text-orange-300 border-orange-400/40',
  BULK_EXPORT:                'text-amber-300 border-amber-400/40',
  HIGH_BLAST_ACCESS:          'text-purple-300 border-purple-400/40',
  CROSS_DEPT_ACCESS:          'text-blue-300 border-blue-400/40',
  HIGH_FAIL_RATE:             'text-red-300 border-red-400/40',
}

function riskGradient(score) {
  if (score >= 70) return 'from-rose-500 to-red-600'
  if (score >= 50) return 'from-orange-400 to-amber-500'
  if (score >= 30) return 'from-yellow-400 to-amber-400'
  return 'from-emerald-400 to-teal-500'
}

function riskLabel(score) {
  if (score >= 70) return { text: 'HIGH', cls: 'text-rose-300 border-rose-400/40 bg-rose-500/10' }
  if (score >= 50) return { text: 'REVIEW', cls: 'text-orange-300 border-orange-400/40 bg-orange-500/10' }
  if (score >= 25) return { text: 'LOW', cls: 'text-yellow-300 border-yellow-400/30 bg-yellow-500/10' }
  return { text: 'OK', cls: 'text-emerald-300 border-emerald-400/30 bg-emerald-500/10' }
}

const PRIVILEGE_ICON = { admin: '🔴', 'power-user': '🟠', user: '🟢', service: '🔵' }

export default function RiskTable({ users, onSelectUser, selectedUser }) {
  const [search, setSearch] = useState('')
  const [filterDept, setFilterDept] = useState('all')
  const [filterPriv, setFilterPriv] = useState('all')
  const [sortKey, setSortKey]  = useState('risk_score')
  const [sortDir, setSortDir]  = useState('desc')
  const [showFilters, setShowFilters] = useState(false)

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
    ? (sortDir === 'asc' ? <ChevronUp size={12} /> : <ChevronDown size={12} />)
    : <ChevronDown size={12} className="opacity-20" />

  return (
    <div className="flex h-full flex-col gap-3">
      {/* Search + filter bar */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        <div className="relative flex-1">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            id="risk-search"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search user, ID, department…"
            className="w-full rounded-xl border border-white/10 bg-white/5 py-2 pl-9 pr-4 text-sm text-slate-200 placeholder-slate-600 outline-none focus:border-cyan-500/40 focus:ring-1 focus:ring-cyan-500/20"
          />
        </div>
        <button
          onClick={() => setShowFilters(f => !f)}
          className={`flex items-center gap-2 rounded-xl border px-4 py-2 text-sm transition ${showFilters ? 'border-cyan-500/40 bg-cyan-500/10 text-cyan-300' : 'border-white/10 bg-white/5 text-slate-300 hover:bg-white/10'}`}
        >
          <SlidersHorizontal size={14} /> Filters
        </button>
        <div className="text-right text-xs text-slate-500">{visible.length} of {users.length} users</div>
      </div>

      {showFilters && (
        <div className="slide-up flex flex-wrap gap-2">
          <select value={filterDept} onChange={e => setFilterDept(e.target.value)}
            className="rounded-xl border border-white/10 bg-slate-900 px-3 py-1.5 text-xs text-slate-300 outline-none focus:border-cyan-500/40">
            {depts.map(d => <option key={d} value={d}>{d === 'all' ? 'All Departments' : d}</option>)}
          </select>
          <select value={filterPriv} onChange={e => setFilterPriv(e.target.value)}
            className="rounded-xl border border-white/10 bg-slate-900 px-3 py-1.5 text-xs text-slate-300 outline-none focus:border-cyan-500/40">
            {privs.map(p => <option key={p} value={p}>{p === 'all' ? 'All Privileges' : p}</option>)}
          </select>
        </div>
      )}

      {/* Table */}
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full min-w-[720px] border-separate border-spacing-0 text-sm">
          <thead className="sticky top-0 z-10">
            <tr className="text-[11px] uppercase tracking-widest text-slate-500">
              {[
                { key: 'username',      label: 'User'       },
                { key: 'department',    label: 'Dept'       },
                { key: 'privilege_level', label: 'Priv'    },
                { key: 'risk_score',    label: 'Risk Score' },
                { key: null,            label: 'Flags'      },
                { key: null,            label: ''           },
              ].map(({ key, label }, i) => (
                <th
                  key={i}
                  onClick={() => key && toggleSort(key)}
                  className={`border-b border-white/8 bg-slate-950/80 px-4 py-3 text-left backdrop-blur ${key ? 'cursor-pointer select-none hover:text-slate-300' : ''}`}
                >
                  <span className="flex items-center gap-1">
                    {label}{key && <SortIcon k={key} />}
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {visible.map((user, i) => {
              const rl = riskLabel(user.risk_score)
              const isSelected = selectedUser?.user_id === user.user_id
              return (
                <tr
                  key={user.user_id}
                  onClick={() => onSelectUser(user)}
                  className={`cursor-pointer border-b border-white/5 transition-colors ${
                    isSelected ? 'bg-cyan-500/8 ring-1 ring-inset ring-cyan-500/20' : user.suppressed ? 'opacity-40 hover:opacity-60' : 'hover:bg-white/4'
                  }`}
                  style={{ animationDelay: `${i * 12}ms` }}
                >
                  {/* User */}
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-full text-[10px] ${user.privilege_level === 'admin' ? 'bg-rose-500/20 text-rose-300' : 'bg-white/10 text-slate-300'}`}>
                        {user.privilege_level === 'admin' ? <Shield size={12} /> : <User size={12} />}
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <div className="font-medium text-white">{user.username}</div>
                          {user.suppressed && (
                            <span className="chip border border-white/15 bg-white/5 text-[10px] text-slate-400">SUPPRESSED</span>
                          )}
                        </div>
                        <div className="text-[11px] text-slate-500 mono">{user.user_id}</div>
                      </div>
                    </div>
                  </td>
                  {/* Dept */}
                  <td className="px-4 py-3 text-slate-300">{user.department}</td>
                  {/* Priv */}
                  <td className="px-4 py-3">
                    <span className="text-xs">{PRIVILEGE_ICON[user.privilege_level] || '⚪'} {user.privilege_level}</span>
                  </td>
                  {/* Score */}
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="w-20">
                        <div className="risk-bar">
                          <div className={`risk-bar-fill bg-gradient-to-r ${riskGradient(user.risk_score)}`} style={{ width: `${user.risk_score}%` }} />
                        </div>
                      </div>
                      <span className={`chip border ${rl.cls}`}>{rl.text} {Number(user.risk_score).toFixed(0)}</span>
                    </div>
                  </td>
                  {/* Flags */}
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {(user.flags || []).slice(0, 2).map(f => (
                        <span key={f} className={`chip border bg-transparent ${FLAG_COLORS[f] || 'text-slate-400 border-white/20'}`}>
                          {f.replace(/_/g, ' ')}
                        </span>
                      ))}
                      {(user.flags || []).length > 2 && (
                        <span className="chip border border-white/15 text-slate-500">+{user.flags.length - 2}</span>
                      )}
                    </div>
                  </td>
                  {/* Action */}
                  <td className="px-4 py-3">
                    <button
                      id={`inspect-${user.user_id}`}
                      onClick={e => { e.stopPropagation(); onSelectUser(user) }}
                      className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-xs font-medium text-white transition hover:border-cyan-500/40 hover:bg-cyan-500/10 hover:text-cyan-300"
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
          <div className="flex h-40 items-center justify-center text-sm text-slate-500">
            No users match your filters.
          </div>
        )}
      </div>
    </div>
  )
}
