const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
const ISO = /(\d{4})-(\d{2})-(\d{2})T(\d{2}:\d{2}:\d{2})(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?/g

// Timestamps stay on the firewall's own clock: the text is reformatted, never converted.
const pretty = (_, y, m, d, time) => `${Number(d)} ${MONTHS[Number(m) - 1]} ${y}, ${time}`

export const fmtTime = iso => (iso ? iso.replace(ISO, pretty) : '')
export const prettifyText = text => (text || '').replace(ISO, pretty)

export function fmtDuration(fromIso, toIso) {
  const secs = Math.round((new Date(toIso) - new Date(fromIso)) / 1000)
  if (!Number.isFinite(secs) || secs < 0) return ''
  if (secs < 60) return `${secs} sec`
  if (secs < 3600) return `${Math.round(secs / 60)} min`
  const hours = Math.floor(secs / 3600)
  const mins = Math.round((secs % 3600) / 60)
  if (hours < 24) return mins ? `${hours} h ${mins} min` : `${hours} h`
  return `${Math.floor(hours / 24)} d ${hours % 24} h`
}

export const OUTCOME = {
  blocked: { label: 'Blocked', tone: 'good', help: 'The firewall stopped every event in this step.' },
  allowed: { label: 'Got through', tone: 'bad', help: 'The firewall allowed every event in this step.' },
  mixed: { label: 'Partly got through', tone: 'warn', help: 'Some events in this step were blocked and some were allowed.' },
}

export const KIND = {
  external_ip: { label: 'External IP', help: 'An address outside your network that took part in this incident.' },
  host: { label: 'Internal host', help: 'A machine inside your network that took part in this incident.' },
  user: { label: 'User account', help: 'An account used or created during this incident.' },
  firewall: { label: 'Firewall', help: 'The FortiGate itself. Control of it can change policy for every network segment.' },
  domain: { label: 'Domain', help: 'A domain name contacted during this incident.' },
}

export const BASIS = {
  observed: {
    label: 'Seen connecting', tone: 'bad', proven: true,
    help: 'The log shows real traffic from a compromised machine to this target.',
  },
  same_segment: {
    label: 'Same network segment', tone: 'warn', proven: false,
    help: 'Shares a network segment with a compromised machine. This is possible, not proven: no such traffic was seen in the log.',
  },
  admin_control: {
    label: 'Firewall admin control', tone: 'bad', proven: false,
    help: 'Whoever controls the firewall can change the policy protecting this segment. No traffic to it is implied.',
  },
}

export const SENSITIVITY_ORDER = ['crown', 'high', 'medium', 'low']
export const SENSITIVITY_LABEL = { crown: 'Crown jewel', high: 'High', medium: 'Medium', low: 'Low' }
