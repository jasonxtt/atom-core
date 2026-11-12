// Pure helpers for the rule form's port entries. No imports, so `npm test` runs them directly.

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

export const TRANSPORT_WITH_NAMES = '带端口或网络条件的规则不能再带域名类条件或客户端条件：DNS 查询时不知道端口'
