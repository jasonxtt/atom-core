import type { Schemas } from '../api/client'
import { rules, upstreamGroups } from './rules'

export type AuditLog = Schemas['AuditLog']

/** The FakeIP group (sing-box), which `upstreams` leaves out. */
export const FAKEIP_GROUP = 'nocnfake'

/** A time as local date and time (`full`) or time of day. */
export function logTime(text: string, full = false): string {
  const at = new Date(text)
  if (Number.isNaN(at.getTime())) return text
  return full ? at.toLocaleString('zh-CN', { hour12: false }) : at.toLocaleTimeString('zh-CN', { hour12: false })
}

export const ms = (value: number) => `${value < 10 ? value.toFixed(2) : value.toFixed(1)} ms`

/**
 * A recorded tag as shown: the rule table's tags (`规则:<备注或 ID>`) by the rule's remark or
 * place, several tags joined by ` · `.
 */
export function tagLabel(key: string | undefined): string {
  if (!key) return '—'
  return key
    .split('|')
    .map((part) => {
      if (!part.startsWith('规则:')) return part
      const name = part.slice(3)
      const at = rules.value.findIndex((rule) => rule.id === name)
      if (at < 0) return `规则 · ${name}`
      return `规则 · ${rules.value[at].remark || `第 ${at + 1} 条`}`
    })
    .join(' · ')
}

/** An upstream group's display name (`domestic`, a custom group, the FakeIP group). */
export function groupLabel(tag: string): string {
  if (tag === FAKEIP_GROUP) return 'FakeIP（sing-box）'
  return upstreamGroups.value.find((group) => group.tag === tag)?.name ?? tag
}

/** The group a recorded upstream (a group tag or one of its upstreams' tags) belongs to. */
export function groupOf(tag: string | undefined): string {
  if (!tag) return '—'
  if (tag === FAKEIP_GROUP || upstreamGroups.value.some((group) => group.tag === tag)) return groupLabel(tag)
  const group = upstreamGroups.value.find((item) => item.upstreams.some((upstream) => upstream.tag === tag))
  return group ? group.name : '—'
}

export const CACHE_STATUS: Record<string, string> = { hit: '命中', miss: '未命中', not_applicable: '未经过缓存', undetermined: '—' }

export function flags(log: AuditLog): string {
  const on = Object.entries(log.response_flags ?? {})
    .filter(([, value]) => value)
    .map(([key]) => key)
  return on.join(' ') || '—'
}

export const answerText = (log: AuditLog) => log.answers.map((answer) => answer.data).join(' ') || log.response_code

const OUTCOMES: Record<string, string> = { response: '应答', failed: '失败', timed_out: '超时', canceled: '取消', interrupted: '中断' }
export const outcomeLabel = (outcome: string) => OUTCOMES[outcome] ?? outcome

/** The attempts of a log (`upstream_diagnostics.attempts`), in order. */
export interface Attempt {
  ordinal: number
  qtype?: number
  entry: string
  peer?: string
  transport?: string
  outcome: string
}

export function attempts(log: AuditLog): Attempt[] {
  const list = (log.upstream_diagnostics as { attempts?: Attempt[] } | undefined)?.attempts
  return Array.isArray(list) ? list : []
}

/** The upstream that answered: its tag and address. */
export function supplier(log: AuditLog): string {
  const selected = (log.upstream_diagnostics as { selected?: { entry?: string; peer?: string } } | undefined)?.selected
  const entry = selected?.entry
  const peer = selected?.peer || log.selected_upstream
  if (entry && peer) return `${entry}（${peer}）`
  return entry || peer || '—'
}

export const QTYPES: Record<number, string> = { 1: 'A', 28: 'AAAA', 5: 'CNAME', 65: 'HTTPS', 12: 'PTR', 6: 'SOA', 15: 'MX', 16: 'TXT' }
