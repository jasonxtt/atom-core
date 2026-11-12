<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { call, client, describe } from '../api/client'
import AppModal from './AppModal.vue'
import LogDetail from './LogDetail.vue'
import { logTime, ms, tagLabel, type AuditLog } from '../composables/dnslog'

/** The recorded queries of one name, client or tag (`filter`), a page at a time, with a few figures. */
const props = defineProps<{
  title: string
  filter: { domain?: string; client_ip?: string; domain_set?: string }
  count: number
  total: number
}>()
const emit = defineEmits<{ close: [] }>()

const LIMIT = 50
const logs = ref<AuditLog[]>([])
const page = ref(1)
const pages = ref(1)
// The page asked for; `page` is the one shown, set only when its logs arrived.
let wanted = 1
const error = ref('')
const loading = ref(true)
const opened = ref<AuditLog | null>(null)
let asked = 0

async function load() {
  const ticket = ++asked
  loading.value = true
  try {
    const { domain, ...rest } = props.filter
    // A name's own queries: `logs/domain` matches the whole name (`logs?domain=` a part of it).
    const answer = domain
      ? await call(client.GET('/audit/logs/domain', { params: { query: { domain, page: wanted, limit: LIMIT } } }))
      : await call(client.GET('/audit/logs', { params: { query: { ...rest, page: wanted, limit: LIMIT } } }))
    if (ticket !== asked) return
    page.value = wanted
    logs.value = answer.logs
    pages.value = Math.max(1, answer.pagination.total_pages)
    error.value = ''
  } catch (failure) {
    if (ticket === asked) error.value = describe(failure)
  } finally {
    if (ticket === asked) loading.value = false
  }
}
onMounted(load)
function go(next: number) {
  wanted = Math.min(Math.max(1, next), pages.value)
  load()
}

const figures = computed(() => {
  const list = logs.value
  const average = list.length ? list.reduce((sum, log) => sum + log.duration_ms, 0) / list.length : null
  const slowest = list.length ? Math.max(...list.map((log) => log.duration_ms)) : null
  return [
    ['查询次数', props.count.toLocaleString()],
    ['占比', props.total ? `${((props.count / props.total) * 100).toFixed(1)}%` : '—'],
    ['本页平均耗时', average === null ? '—' : ms(average)],
    ['本页最大耗时', slowest === null ? '—' : ms(slowest)]
  ]
})
</script>

<template>
  <AppModal v-if="!opened" :title="title" @close="emit('close')">
    <div class="tiles">
      <div v-for="item in figures" :key="item[0]" class="tile">
        <div class="k">{{ item[0] }}</div>
        <div class="v tnum">{{ item[1] }}</div>
      </div>
    </div>
    <div v-if="error" class="err">{{ error }}</div>
    <div class="tblwrap">
      <table>
        <thead><tr><th>时间</th><th>客户端</th><th>域名</th><th>类型</th><th>规则</th><th>耗时</th></tr></thead>
        <tbody>
          <tr v-for="log in logs" :key="log.trace_id" class="crow" tabindex="0" @click="opened = log" @keydown.enter="opened = log">
            <td class="t2 tnum">{{ logTime(log.query_time) }}</td>
            <td class="mono">{{ log.client_ip }}</td>
            <td class="mono">{{ log.query_name }}</td>
            <td>{{ log.query_type }}</td>
            <td>{{ tagLabel(log.domain_set || log.effective_tag) }}</td>
            <td class="tnum">{{ ms(log.duration_ms) }}</td>
          </tr>
          <tr v-if="!logs.length && !loading"><td colspan="6" class="t2">—</td></tr>
        </tbody>
      </table>
    </div>
    <template #footer>
      <span class="t2 tnum" style="margin-right: auto; align-self: center">第 {{ page }} / {{ pages }} 页</span>
      <button class="btn" type="button" :disabled="page <= 1 || loading" @click="go(page - 1)">上一页</button>
      <button class="btn" type="button" :disabled="page >= pages || loading" @click="go(page + 1)">下一页</button>
      <button class="btn" type="button" @click="emit('close')">关闭</button>
    </template>
  </AppModal>
  <LogDetail v-else :log="opened" @close="opened = null" />
</template>
