// Pure helpers for the rule form: port entries, and a sing-box headless rule (JSON) split into
// the form's conditions. No imports, so `npm test` runs them directly.

export interface PortEntries {
  port: number[]
  /** sing-box's `start:end` (either side may be open). */
  port_range: string[]
  bad: string[]
}

const portNumber = (text: string) => (/^\d{1,5}$/.test(text) && +text >= 1 && +text <= 65535 ? +text : null)

/** `start:end` from `start:end` or `start-end` (either side may be open), or null. */
export function portRange(text: string): string | null {
  const parts = /^(\d*)\s*[-:]\s*(\d*)$/.exec(text.trim())
  if (!parts || (!parts[1] && !parts[2])) return null
  const start = parts[1] ? portNumber(parts[1]) : 0
  const end = parts[2] ? portNumber(parts[2]) : 0
  if (start === null || end === null || (start && end && start > end)) return null
  return `${parts[1] ? start : ''}:${parts[2] ? end : ''}`
}

/** Ports and ranges, one per line or separated by commas: `443`, `8000-9000`, `1000:`. */
export function parsePorts(text: string): PortEntries {
  const entries: PortEntries = { port: [], port_range: [], bad: [] }
  for (const raw of text.split(/[\n,，]/)) {
    const item = raw.trim()
    if (!item) continue
    const port = portNumber(item)
    const range = port === null ? portRange(item) : null
    if (port !== null) {
      if (!entries.port.includes(port)) entries.port.push(port)
    } else if (range) {
      if (!entries.port_range.includes(range)) entries.port_range.push(range)
    } else {
      entries.bad.push(item)
    }
  }
  return entries
}

/** The form's text for ports and ranges (`a-b`; an open side stays empty). */
export function portsText(port: number[] = [], ranges: string[] = []): string {
  return [...port.map(String), ...ranges.map((range) => range.replace(':', '-'))].join('\n')
}

export interface HeadlessFields {
  domain: string[]
  suffix: string[]
  keyword: string[]
  regex: string[]
  ip_cidr: string[]
  port: number[]
  port_range: string[]
  network: string[]
  client: string[]
}

type Field = keyof HeadlessFields

/** sing-box headless rule fields the form takes, and where they go. */
const FIELDS: Record<string, Field> = {
  domain: 'domain',
  domain_suffix: 'suffix',
  domain_keyword: 'keyword',
  domain_regex: 'regex',
  ip_cidr: 'ip_cidr',
  port: 'port',
  port_range: 'port_range',
  network: 'network',
  source_ip_cidr: 'client'
}

export const TRANSPORT_WITH_NAMES = '带端口或网络条件的规则不能再带域名类条件或客户端条件：DNS 查询时不知道端口'

/**
 * Splits one sing-box headless rule into the form's fields. A field the form cannot take
 * (`rule_set`, `protocol`, `process_*`, `invert`, …) is an error, never dropped.
 */
export function parseHeadlessRule(text: string): { fields: HeadlessFields } | { error: string } {
  let value: unknown
  try {
    value = JSON.parse(text)
  } catch (failure) {
    return { error: `不是 JSON：${failure instanceof Error ? failure.message : String(failure)}` }
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) return { error: '要一条 sing-box 无头规则（JSON 对象）' }
  const rule = value as Record<string, unknown>
  const unsupported = Object.keys(rule).filter((key) => !(key in FIELDS))
  if (unsupported.length) return { error: `不支持的字段：${unsupported.join('、')}` }
  if (!Object.keys(rule).length) return { error: '规则里没有条件' }
  const fields: HeadlessFields = { domain: [], suffix: [], keyword: [], regex: [], ip_cidr: [], port: [], port_range: [], network: [], client: [] }
  for (const [key, raw] of Object.entries(rule)) {
    const items = Array.isArray(raw) ? raw : [raw]
    const field = FIELDS[key]
    for (const item of items) {
      if (field === 'port') {
        if (typeof item !== 'number' || !Number.isInteger(item) || item < 1 || item > 65535) return { error: `port 的值 ${JSON.stringify(item)} 不是 1 到 65535 的端口` }
        if (!fields.port.includes(item)) fields.port.push(item)
        continue
      }
      if (typeof item !== 'string' || !item.trim()) return { error: `${key} 的值 ${JSON.stringify(item)} 不是字符串` }
      let entry = item.trim()
      if (field === 'port_range') {
        const range = portRange(entry)
        if (!range || !entry.includes(':')) return { error: `port_range 的值 ${JSON.stringify(item)} 无效：写成 起始:结束` }
        entry = range
      } else if (field === 'network') {
        entry = entry.toLowerCase()
        if (entry !== 'tcp' && entry !== 'udp') return { error: `network 的值 ${JSON.stringify(item)} 无效：只能是 tcp 或 udp` }
      } else if (field === 'suffix') {
        // `.example.com` in sing-box is only the subdomains; a suffix here also takes the name itself.
        entry = entry.replace(/^\.+/, '')
        if (!entry) return { error: `domain_suffix 的值 ${JSON.stringify(item)} 无效` }
      }
      const list = fields[field] as string[]
      if (!list.includes(entry)) list.push(entry)
    }
  }
  const names = fields.domain.length + fields.suffix.length + fields.keyword.length + fields.regex.length
  const transport = fields.port.length + fields.port_range.length + fields.network.length
  if (transport && (names || fields.client.length)) return { error: TRANSPORT_WITH_NAMES }
  if (fields.client.length && fields.ip_cidr.length) return { error: '有客户端条件时不能带 IP 部分' }
  if (!names && !transport && !fields.client.length && !fields.ip_cidr.length) return { error: '规则里没有条件' }
  return { fields }
}
