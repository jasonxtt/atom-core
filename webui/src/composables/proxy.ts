import { computed, ref } from 'vue'
import { ApiError, call, client, describe, type Schemas } from '../api/client'
import { toast } from './toast'

export type Node = Schemas['Node']
export type Group = Schemas['Group']
type Runtime = { groups: Record<string, { now: string }>; nodes: Record<string, { delay: number | null; time: string | null }> }

/** A group card: a node group, or Final shown as one (`final`). */
export interface GroupView {
  id: string
  name: string
  type: 'selector' | 'urltest'
  members: string[]
  builtin: boolean
  group?: Group
}

export const FINAL = 'final'
export const FINAL_NAME = '兜底分组'

/** The proxy state (nodes, groups, Final share one `version`) and sing-box's runtime view. */
export const nodes = ref<Node[]>([])
export const groups = ref<Group[]>([])
export const order = ref<string[]>([])
export const final = ref<Schemas['Final'] | null>(null)
export const version = ref(0)
export const runtime = ref<Runtime | null>(null)

export async function loadProxy() {
  const [nodeList, groupList, finalState] = await Promise.all([
    call(client.GET('/nodes')),
    call(client.GET('/groups')),
    call(client.GET('/final'))
  ])
  nodes.value = nodeList.nodes
  groups.value = groupList.groups
  order.value = groupList.order
  final.value = finalState
  version.value = Math.max(nodeList.version, groupList.version, finalState.version)
}

/** `GET runtime`; null while sing-box has no configuration or does not answer. */
export async function loadRuntime() {
  try {
    runtime.value = (await call(client.GET('/runtime'))) as Runtime
  } catch {
    runtime.value = null
  }
}

/** A write refused for a stale version reloads the state; other failures are shown. */
export async function reportFailure(error: unknown) {
  if (error instanceof ApiError && error.status === 409 && error.body?.version !== undefined) {
    await loadProxy().catch(() => {})
    toast('warn', '节点或节点组已在别处修改，已载入最新内容，请重试（409）')
  } else {
    toast('bad', describe(error))
  }
}

export const groupViews = computed<GroupView[]>(() => {
  const byId = new Map(groups.value.map((group) => [group.id, group]))
  return order.value.flatMap((id): GroupView[] => {
    if (id === FINAL) {
      return final.value ? [{ id, name: FINAL_NAME, type: 'selector', members: final.value.members, builtin: true }] : []
    }
    const group = byId.get(id)
    return group ? [{ id, name: group.name, type: group.type, members: group.members, builtin: group.builtin, group }] : []
  })
})

const names = computed(() => {
  const map = new Map<string, string>([
    [FINAL, FINAL_NAME],
    ['direct', '直连'],
    ['block', '拒绝']
  ])
  for (const node of nodes.value) map.set(node.id, node.name)
  for (const group of groups.value) map.set(group.id, group.name)
  return map
})

export const nameOf = (id: string | undefined) => (id ? (names.value.get(id) ?? id) : '—')
export const isGroup = (id: string) => id === FINAL || id.startsWith('g-')

/** The member a group uses now (sing-box's view, else its saved choice, else the first). */
export function currentOf(id: string): string | undefined {
  const now = runtime.value?.groups[id]?.now
  if (now) return now
  if (id === FINAL) return final.value?.selected || final.value?.members[0]
  const group = groups.value.find((item) => item.id === id)
  return group?.now || group?.selected || group?.members[0]
}

/** The node a member's traffic ends at (following groups that choose groups). */
export function leafOf(id: string | undefined): string | undefined {
  const seen = new Set<string>()
  let current = id
  while (current && isGroup(current) && !seen.has(current)) {
    seen.add(current)
    current = currentOf(current)
  }
  return current && !isGroup(current) ? current : undefined
}

export function delayOf(id: string | undefined) {
  const leaf = leafOf(id)
  return leaf ? runtime.value?.nodes[leaf] : undefined
}

/** Records a delay answer (until the next runtime read replaces it). */
export function recordDelay(id: string, delay: number | null | undefined) {
  if (!runtime.value) return
  runtime.value.nodes[id] = { delay: delay ?? null, time: new Date().toISOString() }
}
