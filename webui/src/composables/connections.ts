import { ref } from 'vue'
import { call, client } from '../api/client'
import { FINAL, nameOf } from './proxy'

/** One connection of sing-box's snapshot (`GET connections`), as the table shows it. */
export interface Conn {
  id: string
  host: string
  ip: string
  port: string
  src: string
  srcPort: string
  network: string
  inbound: string
  /** Outbound tags outermost first (sing-box lists them innermost first). */
  chain: string[]
  rule: string
  download: number
  upload: number
  dlRate: number
  ulRate: number
  start: number
  closedAt?: number
  raw: Record<string, unknown>
}

interface Snapshot {
  id: string
  metadata?: Record<string, string>
  chains?: string[]
  rule?: string
  rulePayload?: string
  download?: number
  upload?: number
  start?: string
}

/**
 * The rule in atom's words. sing-box names `final` both for a FakeIP name with a binding (the
 * chain then starts at the bound group) and for one without (it starts at Final).
 */
export function ruleLabel(rule: string, chain: string[]): string {
  const outer = chain[0]
  if (rule === 'final' || rule === '') {
    if (!outer || outer === FINAL) return '兜底分组'
    if (outer === 'direct') return '直连'
    return `绑定 → ${nameOf(outer)}`
  }
  if (rule.includes('ip_cidr')) return `IP 规则 → ${nameOf(outer)}`
  if (outer === 'direct') return '直连'
  if (outer === 'block') return '拒绝'
  return rule.replace(/\b(?:n|g)-[0-9a-f]{8}\b|\bfinal\b/g, (id) => nameOf(id))
}

const CLOSED_KEPT = 500
export const active = ref<Conn[]>([])
export const closed = ref<Conn[]>([])
export const totals = ref({ down: 0, up: 0, downRate: 0, upRate: 0 })
export const failure = ref('')
let last: { at: number; byId: Map<string, Conn>; down: number; up: number } | null = null

/** Takes one snapshot: rates are the growth since the previous one. */
export async function sample() {
  let snapshot: { downloadTotal?: number; uploadTotal?: number; connections?: unknown[] | null }
  try {
    snapshot = await call(client.GET('/connections'))
    failure.value = ''
  } catch (error) {
    failure.value = error instanceof Error ? error.message : String(error)
    return
  }
  const at = Date.now()
  const seconds = last ? (at - last.at) / 1000 : 0
  const byId = new Map<string, Conn>()
  for (const item of (snapshot.connections ?? []) as Snapshot[]) {
    const meta = item.metadata ?? {}
    const chain = [...(item.chains ?? [])].reverse()
    const before = last?.byId.get(item.id)
    const download = item.download ?? 0
    const upload = item.upload ?? 0
    byId.set(item.id, {
      id: item.id,
      host: meta.host || meta.destinationIP || '',
      ip: meta.destinationIP || '',
      port: meta.destinationPort || '',
      src: meta.sourceIP || '',
      srcPort: meta.sourcePort || '',
      network: meta.network || '',
      inbound: meta.type || '',
      chain,
      rule: ruleLabel(item.rule ?? '', chain),
      download,
      upload,
      dlRate: before && seconds > 0 ? Math.max(0, download - before.download) / seconds : 0,
      ulRate: before && seconds > 0 ? Math.max(0, upload - before.upload) / seconds : 0,
      start: item.start ? Date.parse(item.start) : at,
      raw: item as unknown as Record<string, unknown>
    })
  }
  if (last) {
    const gone = [...last.byId.values()].filter((conn) => !byId.has(conn.id)).map((conn) => ({ ...conn, dlRate: 0, ulRate: 0, closedAt: at }))
    if (gone.length) closed.value = [...gone, ...closed.value].slice(0, CLOSED_KEPT)
  }
  const down = snapshot.downloadTotal ?? 0
  const up = snapshot.uploadTotal ?? 0
  totals.value = {
    down,
    up,
    downRate: last && seconds > 0 ? Math.max(0, down - last.down) / seconds : 0,
    upRate: last && seconds > 0 ? Math.max(0, up - last.up) / seconds : 0
  }
  active.value = [...byId.values()]
  last = { at, byId, down, up }
}

/** Forgets the previous snapshot (after a pause, so rates do not span it). */
export function restart() {
  last = null
}
