import { computed, ref } from 'vue'
import { call, client, type Schemas } from '../api/client'

/** `GET status`, shared by the top bar and the pages (the shell polls it). */
export const status = ref<Schemas['Status'] | null>(null)
export const statusError = ref('')

// Status reads apply in the order they were sent (a late answer is dropped).
let ticket = 0
let applied = 0

export async function refreshStatus() {
  const mine = ++ticket
  try {
    const answer = await call(client.GET('/status'))
    if (mine < applied) return
    applied = mine
    status.value = answer
    statusError.value = ''
  } catch (error) {
    if (mine >= applied) {
      applied = mine
      statusError.value = error instanceof Error ? error.message : String(error)
    }
    throw error
  }
}

export const health = computed(() => {
  if (statusError.value) return { kind: 'bad', text: '无法连接' }
  const current = status.value
  if (!current) return { kind: 'idle', text: '连接中' }
  if (!current.singbox.running) return { kind: 'bad', text: `${backendName.value} 未运行` }
  if (current.warnings.empty_groups?.length) return { kind: 'warn', text: '有空组' }
  if (!current.singbox.in_sync) return { kind: 'warn', text: '配置未同步' }
  return { kind: 'ok', text: '运行中 · 已同步' }
})

/** The active proxy kernel (`status.singbox` describes it whichever it is; sing-box when the field is absent). */
export const backendName = computed(() => status.value?.backend ?? 'sing-box')

/** The kernel's version number (Clash API answers `sing-box 1.14.4-atom`, `Mihomo Meta v1.19`). */
export const backendVersion = computed(() => status.value?.singbox.version?.replace(/^(sing-box|mihomo(\s+meta)?)\s+/i, '') ?? '')

/** When the kernel started (unix seconds); null when it is not running or the field is absent. */
export const backendStartedAt = computed(() => status.value?.singbox?.started_at ?? null)

export const isMihomo = computed(() => status.value?.backend === 'mihomo')
