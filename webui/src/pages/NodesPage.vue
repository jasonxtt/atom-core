<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { call, client, describe } from '../api/client'
import AppModal from '../components/AppModal.vue'
import NodeModal from '../components/NodeModal.vue'
import { limited, testNode, testing } from '../composables/delay'
import { usePoll } from '../composables/poll'
import { loadProxy, loadRuntime, nameOf, nodes, reportFailure, runtime, version, type Node } from '../composables/proxy'
import { refreshStatus } from '../composables/status'
import { toast } from '../composables/toast'
import { latency, type Latency } from '../format'

const error = ref('')
onMounted(async () => {
  try {
    await loadProxy()
  } catch (failure) {
    error.value = describe(failure)
  }
})
usePoll(loadRuntime, 5000)

const labels: Record<Latency, string> = { idle: '未测速', ok: '正常', warn: '偏高', bad: '失败' }
function testOf(node: Node) {
  const test = runtime.value?.nodes[node.id]
  const kind = latency(test?.delay, test?.time)
  return { kind, label: labels[kind], text: test?.delay != null ? `${test.delay} ms` : kind === 'bad' ? '超时' : '—', delay: test?.delay ?? null }
}

const stats = computed(() => {
  const counts = { ok: 0, warn: 0, bad: 0, idle: 0 }
  for (const node of nodes.value) counts[testOf(node).kind]++
  return counts
})

const search = ref('')
const sort = ref<'name' | 'delay'>('name')
const shown = computed(() => {
  const query = search.value.trim().toLowerCase()
  const list = nodes.value.filter((node) => !query || `${node.name} ${node.server ?? ''}`.toLowerCase().includes(query))
  if (sort.value === 'name') return [...list].sort((a, b) => a.name.localeCompare(b.name, 'zh-CN'))
  const key = (node: Node) => testOf(node).delay ?? Number.POSITIVE_INFINITY
  return [...list].sort((a, b) => key(a) - key(b))
})

const testingAll = ref(false)
async function testAll() {
  testingAll.value = true
  await limited(nodes.value.map((node) => () => testNode(node.id)))
  testingAll.value = false
}

async function copy(text: string) {
  try {
    await navigator.clipboard.writeText(text)
    toast('ok', '已复制')
  } catch {
    toast('bad', '复制失败')
  }
}

const editing = ref<Node | null>(null)
const importing = ref(false)
const removing = ref<Node | null>(null)
const busy = ref(false)
async function remove() {
  const node = removing.value
  if (!node) return
  busy.value = true
  try {
    await call(client.DELETE('/nodes/{id}', { params: { path: { id: node.id }, query: { version: version.value } } }))
    toast('ok', `已删除「${node.name}」`)
    await loadProxy().catch(() => {})
  } catch (failure) {
    await reportFailure(failure)
  } finally {
    removing.value = null
    busy.value = false
    refreshStatus().catch(() => {})
  }
}
</script>

<template>
  <div v-if="error" class="err">{{ error }}</div>
  <div class="card">
    <div class="grid g4" style="gap: 8px">
      <div class="tile"><div class="k">总节点</div><div class="big">{{ nodes.length }}</div></div>
      <div class="tile"><div class="k">正常</div><div class="big" style="color: var(--ok)">{{ stats.ok + stats.warn }}</div></div>
      <div class="tile"><div class="k">失败</div><div class="big" style="color: var(--bad)">{{ stats.bad }}</div></div>
      <div class="tile"><div class="k">未测速</div><div class="big muted">{{ stats.idle }}</div></div>
    </div>
  </div>
  <div class="card">
    <div class="hd">
      <h2>节点</h2>
      <span class="tag">{{ nodes.length }}</span>
      <span class="sp"></span>
      <input v-model="search" class="inp" style="width: 200px" placeholder="搜索名称或地址" aria-label="搜索节点" />
      <select v-model="sort" class="inp" style="width: auto" aria-label="排序">
        <option value="name">按名称</option>
        <option value="delay">按延迟</option>
      </select>
      <button class="btn" type="button" :disabled="testingAll" @click="testAll">全部测速</button>
      <button class="btn pri" type="button" @click="importing = true">＋ 添加节点</button>
    </div>
    <div class="ncards">
      <div v-for="node in shown" :key="node.id" class="ncard">
        <div class="row">
          <span class="tag">{{ (node.type ?? '').toUpperCase() }}</span>
          <span class="pill" :class="testOf(node).kind">{{ testOf(node).label }}</span>
          <span class="sp"></span>
          <span class="tnum" :style="{ color: `var(--${testOf(node).kind === 'idle' ? 'muted' : testOf(node).kind})` }">{{ testing[node.id] ? '…' : testOf(node).text }}</span>
        </div>
        <div class="nm">{{ node.name }}</div>
        <div class="t2 mono">{{ node.server }}:{{ node.server_port }}</div>
        <div class="hint">所在组：{{ node.groups.map(nameOf).join('、') || '无' }}</div>
        <div class="acts">
          <button class="ico" type="button" aria-label="复制地址" title="复制地址" @click="copy(`${node.server}:${node.server_port}`)">
            <svg viewBox="0 0 24 24"><rect x="8" y="8" width="12" height="12" rx="2" /><path d="M4 16V4h12" /></svg>
          </button>
          <button class="ico" type="button" aria-label="测速" title="测速" @click="testNode(node.id)">
            <svg viewBox="0 0 24 24"><path d="M13 3L5 14h6l-1 7 8-11h-6z" /></svg>
          </button>
          <button class="ico" type="button" aria-label="编辑" title="编辑" @click="editing = node">
            <svg viewBox="0 0 24 24"><path d="M4 20h4L19 9l-4-4L4 16z" /></svg>
          </button>
          <button class="ico" type="button" aria-label="删除" title="删除" style="color: var(--bad)" @click="removing = node">
            <svg viewBox="0 0 24 24"><path d="M5 7h14M9 7V4h6v3M7 7l1 13h8l1-13" /></svg>
          </button>
        </div>
      </div>
    </div>
  </div>

  <NodeModal v-if="importing" @close="importing = false" />
  <NodeModal v-if="editing" :node="editing" @close="editing = null" />
  <AppModal v-if="removing" :title="`删除节点「${removing.name}」`" @close="removing = null">
    <div v-if="removing.groups.length">它会从 {{ removing.groups.map(nameOf).join('、') }} 中移除。</div>
    <template #footer>
      <button class="btn" type="button" @click="removing = null">取消</button>
      <button class="btn red" type="button" :disabled="busy" @click="remove">删除</button>
    </template>
  </AppModal>
</template>
