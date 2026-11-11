<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { call, client, describe, type Schemas } from '../api/client'
import DnsTabs from '../components/DnsTabs.vue'

const PAGE_SIZE = 50
const logs = ref<Schemas['AuditLog'][]>([])
const page = ref(1)
const pages = ref(1)
const total = ref(0)
const search = ref('')
const set = ref('')
const sets = ref<string[]>([])
const error = ref('')
const loading = ref(false)
let asked = 0

async function load() {
  const ticket = ++asked
  loading.value = true
  try {
    const query: { page: number; limit: number; q?: string; domain_set?: string } = { page: page.value, limit: PAGE_SIZE }
    if (search.value.trim()) query.q = search.value.trim()
    if (set.value) query.domain_set = set.value
    const answer = await call(client.GET('/audit/logs', { params: { query } }))
    if (ticket !== asked) return
    logs.value = answer.logs
    pages.value = Math.max(1, answer.pagination.total_pages)
    total.value = answer.pagination.total_items
    error.value = ''
  } catch (failure) {
    if (ticket === asked) error.value = describe(failure)
  } finally {
    if (ticket === asked) loading.value = false
  }
}

onMounted(async () => {
  load()
  try {
    sets.value = (await call(client.GET('/audit/rank/domain_set', { params: { query: { limit: 50 } } }))).map((item) => item.key)
  } catch {
    sets.value = []
  }
})

let timer: ReturnType<typeof setTimeout> | undefined
watch(search, () => {
  clearTimeout(timer)
  timer = setTimeout(() => {
    page.value = 1
    load()
  }, 300)
})
watch(set, () => {
  page.value = 1
  load()
})
function go(next: number) {
  page.value = Math.min(Math.max(1, next), pages.value)
  load()
}

const time = (text: string) => {
  const at = new Date(text)
  return Number.isNaN(at.getTime()) ? text : at.toLocaleTimeString('zh-CN', { hour12: false })
}
const answers = (log: Schemas['AuditLog']) => log.answers.map((answer) => answer.data).join(' ') || log.response_code
</script>

<template>
  <DnsTabs />
  <div class="card">
    <div class="hd">
      <input v-model="search" class="inp" style="width: 240px" placeholder="域名、客户端或应答 IP" aria-label="搜索日志" autocomplete="off" />
      <select v-model="set" class="inp" style="width: auto" aria-label="命中分类">
        <option value="">全部分类</option>
        <option v-for="item in sets" :key="item" :value="item">{{ item }}</option>
      </select>
      <span class="sp"></span>
      <span class="t2 tnum">共 {{ total.toLocaleString() }} 条 · 第 {{ page }} / {{ pages }} 页</span>
      <button class="btn sm" type="button" :disabled="page <= 1 || loading" @click="go(page - 1)">上一页</button>
      <button class="btn sm" type="button" :disabled="page >= pages || loading" @click="go(page + 1)">下一页</button>
      <button class="btn sm" type="button" :disabled="loading" @click="load">刷新</button>
    </div>
    <div v-if="error" class="err">{{ error }}</div>
    <div class="tblwrap">
      <table>
        <thead>
          <tr><th>时间</th><th>客户端</th><th>域名</th><th>类型</th><th>分类</th><th>上游</th><th>耗时</th><th>应答</th></tr>
        </thead>
        <tbody>
          <tr v-for="log in logs" :key="log.trace_id">
            <td class="t2 tnum">{{ time(log.query_time) }}</td>
            <td class="mono">{{ log.client_ip }}</td>
            <td class="mono">{{ log.query_name }}</td>
            <td>{{ log.query_type }}</td>
            <td><span v-if="log.domain_set || log.effective_tag" class="pill acc">{{ log.domain_set || log.effective_tag }}</span></td>
            <td class="t2 mono">{{ log.selected_upstream || log.final_upstream || '—' }}</td>
            <td class="tnum">{{ log.duration_ms.toFixed(1) }} ms</td>
            <td class="mono t2" style="white-space: normal; overflow-wrap: anywhere; min-width: 160px">{{ answers(log) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
