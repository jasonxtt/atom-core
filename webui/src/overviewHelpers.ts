/** Pure helpers for the overview dashboard: traffic window config, connection breakdown, and cache parsing. */

export type TrafficWindow = '3m' | '15m' | '1h'
export type BreakdownDim = 'group' | 'client' | 'host'

export interface TrafficSample {
  /** Unix timestamp in milliseconds. */
  ts: number
  /** Download throughput in bytes/sec. */
  down: number
  /** Upload throughput in bytes/sec. */
  up: number
}

export interface WindowMeta {
  key: TrafficWindow
  label: string
  stepMs: number
  slots: number
  axisLabels: string[]
}

export const TRAFFIC_WINDOWS: Record<TrafficWindow, WindowMeta> = {
  '3m': { key: '3m', label: '3 分钟', stepMs: 2_000, slots: 90, axisLabels: ['-3m', '-2m', '-1m', '现在'] },
  '15m': { key: '15m', label: '15 分钟', stepMs: 15_000, slots: 60, axisLabels: ['-15m', '-10m', '-5m', '现在'] },
  '1h': { key: '1h', label: '1 小时', stepMs: 60_000, slots: 60, axisLabels: ['-60m', '-40m', '-20m', '现在'] }
}

export interface ConnectionLike {
  host: string
  ip: string
  src: string
  network: string
  chain: string[]
  download: number
  upload: number
  dlRate: number
  ulRate: number
}

export interface BreakdownItem {
  key: string
  name: string
  sub: string
  rate: number
  total: number
  count: number
  color: string
}

export interface BreakdownSummary {
  items: BreakdownItem[]
  /** True when ranked by live speed; false when idle and ranked by cumulative bytes. */
  byRate: boolean
  clients: number
  tcp: number
  udp: number
  proxyShare: number | null
  directShare: number | null
}

const COLORS = ['var(--c1)', 'var(--c4)', 'var(--c2)', 'var(--c3)', 'var(--c5)']

function trafficTag(tag: string): string {
  if (tag === 'DIRECT' || tag === 'COMPATIBLE') return 'direct'
  if (tag === 'REJECT' || tag === 'REJECT-DROP') return 'block'
  return tag
}

/** Aggregates active connections by group, client IP, or host for the overview breakdown card. */
export function aggregateTraffic(
  conns: readonly ConnectionLike[],
  dim: BreakdownDim,
  nameOf: (id: string | undefined) => string,
  limit = 5
): BreakdownSummary {
  const clientSet = new Set<string>()
  let tcp = 0
  let udp = 0
  let proxyRate = 0
  let directRate = 0
  let proxyTotal = 0
  let directTotal = 0

  interface Acc {
    key: string
    name: string
    sub: string
    rate: number
    total: number
    count: number
    leafCounts: Map<string, number>
  }
  const map = new Map<string, Acc>()

  for (const conn of conns) {
    if (conn.src) clientSet.add(conn.src)
    const net = conn.network.toLowerCase()
    if (net.startsWith('tcp')) tcp++
    else if (net.startsWith('udp')) udp++

    const outer = trafficTag(conn.chain[0] || 'direct')
    const leaf = trafficTag(conn.chain[conn.chain.length - 1] || outer)
    const rate = Math.max(0, conn.dlRate) + Math.max(0, conn.ulRate)
    const total = Math.max(0, conn.download) + Math.max(0, conn.upload)

    if (leaf === 'direct') {
      directRate += rate
      directTotal += total
    } else if (leaf !== 'block') {
      proxyRate += rate
      proxyTotal += total
    }

    let key: string
    let name: string
    let subTag = ''
    if (dim === 'group') {
      key = outer
      name = nameOf(outer)
      subTag = outer === 'direct' ? '国内直连' : outer === 'block' ? '已屏蔽' : leaf && leaf !== outer ? `→ ${nameOf(leaf)}` : ''
    } else if (dim === 'client') {
      key = conn.src || 'local'
      name = conn.src || '本机'
    } else {
      key = conn.host || conn.ip || 'unknown'
      name = conn.host || conn.ip || '未知目标'
      subTag = nameOf(outer)
    }

    let acc = map.get(key)
    if (!acc) {
      acc = { key, name, sub: '', rate: 0, total: 0, count: 0, leafCounts: new Map() }
      map.set(key, acc)
    }
    acc.rate += rate
    acc.total += total
    acc.count += 1
    if (subTag) acc.leafCounts.set(subTag, (acc.leafCounts.get(subTag) ?? 0) + 1)
  }

  const all = [...map.values()]
  const byRate = all.some((item) => item.rate > 0)
  all.sort((a, b) => (byRate ? b.rate - a.rate || b.total - a.total : b.total - a.total || b.count - a.count))

  const items: BreakdownItem[] = all.slice(0, limit).map((acc, index) => {
    let topTag = ''
    let bestCount = 0
    for (const [tag, count] of acc.leafCounts) {
      if (count > bestCount) {
        bestCount = count
        topTag = tag
      }
    }
    let sub: string
    if (dim === 'client') {
      sub = `${acc.count} 连接`
    } else if (dim === 'host') {
      sub = topTag ? `${topTag} · ${acc.count} 连接` : `${acc.count} 连接`
    } else {
      sub = topTag || `${acc.count} 连接`
    }
    return {
      key: acc.key,
      name: acc.name,
      sub,
      rate: acc.rate,
      total: acc.total,
      count: acc.count,
      color: COLORS[index % COLORS.length]
    }
  })

  const splitRate = proxyRate + directRate
  const splitTotal = proxyTotal + directTotal
  let proxyShare: number | null = null
  let directShare: number | null = null
  if (splitRate > 0) {
    proxyShare = Math.round((proxyRate / splitRate) * 100)
    directShare = 100 - proxyShare
  } else if (splitTotal > 0) {
    proxyShare = Math.round((proxyTotal / splitTotal) * 100)
    directShare = 100 - proxyShare
  }

  return {
    items,
    byRate,
    clients: clientSet.size,
    tcp,
    udp,
    proxyShare,
    directShare
  }
}

/** Appends or updates a traffic bucket in place, preserving strict capacity. */
export function appendTrafficSample(
  series: TrafficSample[],
  sample: TrafficSample,
  stepMs: number,
  cap: number
): TrafficSample[] {
  const bucketTs = Math.floor(sample.ts / stepMs) * stepMs
  const nextPoint: TrafficSample = { ts: bucketTs, down: Math.max(0, sample.down), up: Math.max(0, sample.up) }
  const copy = series.slice()
  const last = copy[copy.length - 1]
  if (last && last.ts === bucketTs) {
    copy[copy.length - 1] = nextPoint
  } else if (!last || bucketTs > last.ts) {
    copy.push(nextPoint)
    if (copy.length > cap) copy.splice(0, copy.length - cap)
  }
  return copy
}

/** Picks a clean power-of-two friendly ceiling in bytes/sec for the traffic chart Y-axis. */
export function niceTrafficCeiling(peakBytesPerSec: number): number {
  const floor = 128 * 1024 // 128 KB/s minimum visual floor when idle
  const target = Math.max(peakBytesPerSec * 1.18, floor)
  const pow = Math.pow(2, Math.floor(Math.log2(target)))
  for (const mult of [1, 1.25, 1.5, 2]) {
    if (pow * mult >= target) return pow * mult
  }
  return pow * 2
}

/** Validates a restored overview cache snapshot against a freshness TTL. */
export function isCacheFresh(savedAt: unknown, now: number, ttlMs: number): boolean {
  return typeof savedAt === 'number' && Number.isFinite(savedAt) && now >= savedAt && now - savedAt <= ttlMs
}
