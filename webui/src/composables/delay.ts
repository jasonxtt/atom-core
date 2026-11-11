import { reactive } from 'vue'
import { ApiError, call, client, describe } from '../api/client'
import { FINAL, final, groups, isGroup, loadRuntime, recordDelay } from './proxy'
import { toast } from './toast'

/** Tests running now, by key (a node ID, `g:<group>`, `m:<member>`). */
export const testing = reactive<Record<string, boolean>>({})

/** Tests one node; `key` marks what shows the test (default: the node). */
export async function testNode(id: string, key = id) {
  testing[key] = true
  try {
    const answer = await call(client.POST('/nodes/{id}/delay', { params: { path: { id } }, body: {} }))
    recordDelay(id, answer.delay)
  } catch (error) {
    // sing-box could not reach it (502) or did not answer: a failed test, not an untested node.
    if (!(error instanceof ApiError) || error.status === 0 || error.status >= 500) recordDelay(id, null)
    toast('bad', describe(error))
  } finally {
    delete testing[key]
  }
}

/** Tests every member of a group (or Final) through sing-box. */
export async function testGroup(id: string) {
  const key = `g:${id}`
  testing[key] = true
  try {
    const answer = await call(client.POST('/groups/{id}/delay', { params: { path: { id } }, body: {} }))
    // The answer lists the members that answered; a node member left out failed (and sing-box
    // dropped its history).
    const delays = (answer.delays ?? {}) as Record<string, number>
    const members = id === FINAL ? (final.value?.members ?? []) : (groups.value.find((group) => group.id === id)?.members ?? [])
    for (const member of members) if (!isGroup(member)) recordDelay(member, delays[member] ?? null)
  } catch (error) {
    toast('bad', describe(error))
  } finally {
    await loadRuntime()
    delete testing[key]
  }
}

/** Runs `tasks` with at most `limit` at a time. */
export async function limited(tasks: (() => Promise<void>)[], limit = 4) {
  let next = 0
  const worker = async () => {
    while (next < tasks.length) await tasks[next++]()
  }
  await Promise.all(Array.from({ length: Math.min(limit, tasks.length) }, worker))
}
