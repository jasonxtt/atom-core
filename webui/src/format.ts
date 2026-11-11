/** Shared display helpers. */

export function bytes(value: number): string {
  if (!Number.isFinite(value) || value < 0) return '—'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let size = value
  let unit = 0
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024
    unit++
  }
  return `${size < 10 && unit ? size.toFixed(1) : Math.round(size)} ${units[unit]}`
}

export const rate = (value: number) => `${bytes(value)}/s`

/** How long ago a Unix time (seconds) was. */
export function ago(at: number, now = Date.now() / 1000): string {
  const seconds = Math.max(0, Math.round(now - at))
  if (seconds < 60) return `${seconds} 秒前`
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时前`
  return `${Math.floor(seconds / 86400)} 天前`
}

export function duration(seconds: number): string {
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  if (days) return `${days} 天 ${hours} 小时`
  if (hours) return `${hours} 小时 ${minutes} 分钟`
  if (minutes) return `${minutes} 分钟`
  return `${Math.max(0, Math.floor(seconds))} 秒`
}

export type Latency = 'ok' | 'warn' | 'bad' | 'idle'

/**
 * A delay test: `delay` null with a `time` is a failed test, both null an untested node. A
 * test that answered is never a failure: under 200 ms is good, slower is high.
 */
export function latency(delay: number | null | undefined, time?: string | null): Latency {
  if (delay == null) return time ? 'bad' : 'idle'
  return delay < 200 ? 'ok' : 'warn'
}

export function latencyText(delay: number | null | undefined, time?: string | null): string {
  if (delay == null) return time ? '超时' : '—'
  return String(delay)
}

export const triggers: Record<string, string> = {
  nodes: '节点',
  groups: '节点组',
  final: '兜底分组',
  settings: '设置',
  rules: '规则',
  rulesets: '规则集',
  apply: '重新应用',
  startup: '启动'
}
