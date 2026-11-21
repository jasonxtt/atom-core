import { ref } from 'vue'
import { call, client, type Schemas } from '../api/client'
import { loadPool, loadRuntime } from './proxy'
import {
  TRAFFIC_WINDOWS,
  appendTrafficSample,
  isCacheFresh,
  type TrafficSample,
  type TrafficWindow
} from '../overviewHelpers'

const CACHE_KEY = 'atom-overview-cache-v1'
const CACHE_TTL_MS = 180_000
export const SYSTEM_SAMPLES = 60

interface PersistedOverview {
  savedAt: number
  system: Schemas['System'] | null
  shares: { atomdns: number | null; singbox: number | null }
  cpuHistory: number[]
  memHistory: number[]
  trafficWindow: TrafficWindow
  trafficSeries: TrafficSample[]
  liveTraffic: TrafficSample | null
  totals: { down: number; up: number } | null
  dnsStats: { totalQueries: number; avgDurationMs: number } | null
  cacheHit: string | null
}

function readCache(): PersistedOverview | null {
  try {
    const raw = sessionStorage.getItem(CACHE_KEY)
    if (!raw) return null
    const parsed = JSON.parse(raw) as Partial<PersistedOverview>
    if (!isCacheFresh(parsed.savedAt, Date.now(), CACHE_TTL_MS)) return null
    return {
      savedAt: parsed.savedAt as number,
      system: parsed.system ?? null,
      shares: parsed.shares ?? { atomdns: null, singbox: null },
      cpuHistory: Array.isArray(parsed.cpuHistory) ? parsed.cpuHistory.slice(-SYSTEM_SAMPLES) : [],
      memHistory: Array.isArray(parsed.memHistory) ? parsed.memHistory.slice(-SYSTEM_SAMPLES) : [],
      trafficWindow: parsed.trafficWindow === '15m' || parsed.trafficWindow === '1h' ? parsed.trafficWindow : '3m',
      trafficSeries: Array.isArray(parsed.trafficSeries) ? parsed.trafficSeries.slice(-90) : [],
      liveTraffic: parsed.liveTraffic ?? null,
      totals: parsed.totals ?? null,
      dnsStats: parsed.dnsStats ?? null,
      cacheHit: typeof parsed.cacheHit === 'string' ? parsed.cacheHit : null
    }
  } catch {
    return null
  }
}

const restored = readCache()

// Module-level persistent state: survives both SPA tab switches and F5 refresh (via sessionStorage).
export const system = ref<Schemas['System'] | null>(restored?.system ?? null)
export const shares = ref<{ atomdns: number | null; singbox: number | null }>(
  restored?.shares ?? { atomdns: null, singbox: null }
)
export const cpuHistory = ref<number[]>(restored?.cpuHistory ?? [])
export const memHistory = ref<number[]>(restored?.memHistory ?? [])
export const trafficWindow = ref<TrafficWindow>(restored?.trafficWindow ?? '3m')
export const trafficSeries = ref<TrafficSample[]>(restored?.trafficSeries ?? [])
export const liveTraffic = ref<TrafficSample | null>(restored?.liveTraffic ?? null)
export const cachedTotals = ref<{ down: number; up: number } | null>(restored?.totals ?? null)

export const overviewNodes = ref<Schemas['Node'][]>([])
export const overviewGroups = ref<Schemas['Group'][]>([])
export const overviewOrder = ref<string[]>([])
export const overviewRules = ref<Schemas['RuleTable'] | null>(null)
export const overviewSettings = ref<Schemas['Settings'] | null>(null)
export const overviewDns = ref<Schemas['Dns'] | null>(null)
export const dnsStats = ref<{ totalQueries: number; avgDurationMs: number } | null>(restored?.dnsStats ?? null)
export const cacheHit = ref<string | null>(restored?.cacheHit ?? null)

let previousSystem: Schemas['System'] | null = restored?.system ?? null
let lastRecordedCpuTotal: number | null = restored?.system?.cpu?.total_seconds ?? null
let historyTicket = 0

function persistCache() {
  try {
    const payload: PersistedOverview = {
      savedAt: Date.now(),
      system: system.value,
      shares: shares.value,
      cpuHistory: cpuHistory.value.slice(-SYSTEM_SAMPLES),
      memHistory: memHistory.value.slice(-SYSTEM_SAMPLES),
      trafficWindow: trafficWindow.value,
      trafficSeries: trafficSeries.value.slice(-90),
      liveTraffic: liveTraffic.value,
      totals: cachedTotals.value,
      dnsStats: dnsStats.value,
      cacheHit: cacheHit.value
    }
    sessionStorage.setItem(CACHE_KEY, JSON.stringify(payload))
  } catch {
    // Ignore storage quota or private mode restrictions.
  }
}

function pushBounded(list: number[], value: number, cap: number) {
  list.push(value)
  if (list.length > cap) list.splice(0, list.length - cap)
}

/** Fetches `/system` (optionally with server-buffered history for `window`). */
export async function fetchSystem(withHistory: boolean, windowOverride?: TrafficWindow): Promise<boolean> {
  const targetWindow = windowOverride ?? trafficWindow.value
  const ticket = withHistory ? ++historyTicket : historyTicket
  let now: Schemas['System']
  try {
    now = await call(
      client.GET('/system', {
        params: withHistory ? { query: { history: '1', window: targetWindow } } : undefined
      })
    )
  } catch (error) {
    system.value = null
    previousSystem = null
    shares.value = { atomdns: null, singbox: null }
    throw error
  }

  // Drop stale history answers if the user switched windows while in flight.
  if (withHistory && ticket < historyTicket) return false

  let populatedSystemHistory = false
  if (now.history) {
    if (now.history.system.length) {
      cpuHistory.value = now.history.system.map((item) => item.cpu_percent).slice(-SYSTEM_SAMPLES)
      memHistory.value = now.history.system.map((item) => item.memory_used_bytes).slice(-SYSTEM_SAMPLES)
      const tail = now.history.system[now.history.system.length - 1]
      shares.value = { atomdns: tail.atomdns_percent, singbox: tail.singbox_percent }
      populatedSystemHistory = true
    }
    if (now.history.traffic.window === trafficWindow.value) {
      trafficSeries.value = now.history.traffic.points.map((point) => ({
        ts: point.ts * 1000,
        down: point.down_bps,
        up: point.up_bps
      }))
    }
  }

  const cpuTotalNow = now.cpu?.total_seconds ?? null
  const advanced = cpuTotalNow !== null && (lastRecordedCpuTotal === null || cpuTotalNow > lastRecordedCpuTotal)

  if (!now.cpu) {
    shares.value = { atomdns: null, singbox: null }
  } else if (now.rates) {
    shares.value = { atomdns: now.rates.atomdns_percent, singbox: now.rates.singbox_percent }
    if (!populatedSystemHistory && (advanced || !cpuHistory.value.length)) {
      pushBounded(cpuHistory.value, now.rates.cpu_percent, SYSTEM_SAMPLES)
    }
  } else if (!populatedSystemHistory && previousSystem?.cpu) {
    const total = now.cpu.total_seconds - previousSystem.cpu.total_seconds
    if (total > 0) {
      const cpuPct = Math.max(0, Math.min(100, ((now.cpu.busy_seconds - previousSystem.cpu.busy_seconds) / total) * 100))
      pushBounded(cpuHistory.value, cpuPct, SYSTEM_SAMPLES)
      const shareOf = (key: 'atomdns' | 'singbox') => {
        const a = previousSystem?.[key]
        const b = now[key]
        return a && b && a.pid === b.pid
          ? Math.max(0, Math.min(100, ((b.cpu_seconds - a.cpu_seconds) / total) * 100))
          : null
      }
      shares.value = { atomdns: shareOf('atomdns'), singbox: shareOf('singbox') }
    }
  }

  if (!populatedSystemHistory && now.memory && (advanced || !memHistory.value.length)) {
    pushBounded(memHistory.value, Math.max(0, now.memory.total_bytes - now.memory.available_bytes), SYSTEM_SAMPLES)
  }

  if (cpuTotalNow !== null) lastRecordedCpuTotal = cpuTotalNow
  previousSystem = now
  system.value = now

  if (now.traffic) {
    const sample: TrafficSample = {
      ts: now.traffic.ts * 1000,
      down: now.traffic.down_bps,
      up: now.traffic.up_bps
    }
    liveTraffic.value = sample
    if (!withHistory && trafficWindow.value === '3m') {
      const meta = TRAFFIC_WINDOWS['3m']
      trafficSeries.value = appendTrafficSample(trafficSeries.value, sample, meta.stepMs, meta.slots)
    }
  }

  persistCache()
  // True if still missing a first CPU reading (cold boot right after daemon start).
  return Boolean(now.cpu && cpuHistory.value.length === 0)
}

/** Switches the active traffic time window and loads its buffered series from the server. */
export async function selectTrafficWindow(next: TrafficWindow): Promise<void> {
  if (trafficWindow.value === next) return
  trafficWindow.value = next
  persistCache()
  await fetchSystem(true, next)
}

/** Updates cumulative totals and provides a local traffic-rate fallback when `/system` traffic is unavailable. */
export function syncConnectionTotals(downTotal: number, upTotal: number, downRate: number, upRate: number) {
  cachedTotals.value = { down: downTotal, up: upTotal }
  const serverFresh = liveTraffic.value && Date.now() - liveTraffic.value.ts <= 8_000
  if (!serverFresh) {
    const fallback: TrafficSample = { ts: Date.now(), down: downRate, up: upRate }
    liveTraffic.value = fallback
    if (trafficWindow.value === '3m') {
      const meta = TRAFFIC_WINDOWS['3m']
      trafficSeries.value = appendTrafficSample(trafficSeries.value, fallback, meta.stepMs, meta.slots)
    }
  }
  persistCache()
}

/** Loads the overview's node, group, rule, DNS, and cache summary state. */
export async function loadOverviewState() {
  const [nodeList, groupList, ruleTable, settingsNow, dnsNow, auditNow, cachesNow] = await Promise.allSettled([
    call(client.GET('/nodes')),
    call(client.GET('/groups')),
    call(client.GET('/rules')),
    call(client.GET('/settings')),
    call(client.GET('/dns')),
    call(client.GET('/audit/stats')),
    call(client.GET('/caches')),
    loadRuntime(),
    loadPool()
  ])
  if (nodeList.status === 'fulfilled') overviewNodes.value = nodeList.value.nodes
  if (groupList.status === 'fulfilled') {
    overviewGroups.value = groupList.value.groups
    overviewOrder.value = groupList.value.order
  }
  if (ruleTable.status === 'fulfilled') overviewRules.value = ruleTable.value
  if (settingsNow.status === 'fulfilled') overviewSettings.value = settingsNow.value
  if (dnsNow.status === 'fulfilled') overviewDns.value = dnsNow.value
  if (auditNow.status === 'fulfilled') {
    dnsStats.value = {
      totalQueries: auditNow.value.total_queries,
      avgDurationMs: auditNow.value.average_duration_ms
    }
  }
  if (cachesNow.status === 'fulfilled') {
    const queries = cachesNow.value.caches.reduce((sum, item) => sum + item.queries, 0)
    const hits = cachesNow.value.caches.reduce((sum, item) => sum + item.hits, 0)
    cacheHit.value = queries > 0 ? `${((hits / queries) * 100).toFixed(1)}%` : '—'
  }
  persistCache()
}
