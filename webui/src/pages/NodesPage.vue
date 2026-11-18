<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ApiError, call, client, describe } from '../api/client'
import AppModal from '../components/AppModal.vue'
import NodeModal from '../components/NodeModal.vue'
import ProviderModal from '../components/ProviderModal.vue'
import { limited, testNode, testPoolNode, testing } from '../composables/delay'
import { usePoll } from '../composables/poll'
import { loadPool, loadProviders, loadProxy, loadRuntime, nameOf, nodes, poolNodes, providers, providerUpdated, reportFailure, runtime, version, type Node, type Provider } from '../composables/proxy'
import { isMihomo, refreshStatus } from '../composables/status'
import { toast } from '../composables/toast'
import { ago, latency, type Latency } from '../format'

const error = ref('')
onMounted(async () => {
  try {
    await loadProxy()
    await loadProviders()
  } catch (failure) {
    error.value = describe(failure)
  }
})
usePoll(async () => {
  await loadRuntime()
  await loadPool()
}, 5000)

const labels: Record<Latency, string> = { idle: '未测速', ok: '正常', warn: '偏高', bad: '失败' }

/** A manual node or a subscription node, as one card. */
interface Item {
  id: string
  name: string
  type: string
  /** The subscription's ID; '' for a manual node. */
  source: string
  sourceName: string
  addr: string
  groups: string[]
  node?: Node
  inactive: string
  kind: Latency
  label: string
  text: string
  delay: number | null
}
function itemOf(node: Node): Item {
  const test = runtime.value?.nodes[node.id]
  const kind = latency(test?.delay, test?.time)
  return {
    id: node.id, name: node.name, type: (node.type ?? '').toUpperCase(), source: '', sourceName: '手动', addr: `${node.server}:${node.server_port}`,
    groups: node.groups, node, inactive: node.active === false ? (node.inactive_reason ?? '不生效') : '',
    kind, label: labels[kind], text: test?.delay != null ? `${test.delay} ms` : kind === 'bad' ? '超时' : '—', delay: test?.delay ?? null
  }
}
function itemOfPool(node: (typeof poolNodes.value)[number]): Item {
  const delay = node.delay ?? null
  const kind = latency(delay, node.alive === false ? 'x' : null)
  return {
    id: node.id, name: node.name, type: (node.type ?? '').toUpperCase(), source: node.provider_id, sourceName: node.provider_name, addr: '',
    groups: [], inactive: '', kind, label: labels[kind], text: delay != null ? `${delay} ms` : kind === 'bad' ? '超时' : '—', delay
  }
}
const items = computed(() => [...nodes.value.map(itemOf), ...(isMihomo.value ? poolNodes.value.map(itemOfPool) : [])])

const stats = computed(() => {
  const counts = { ok: 0, warn: 0, bad: 0, idle: 0 }
  for (const item of items.value) if (!item.inactive) counts[item.kind]++
  return counts
})

const search = ref('')
const sort = ref<'name' | 'delay'>('name')
// '' every node, 'manual', or a subscription's ID.
const source = ref('')
const activeSource = computed(() => (isMihomo.value && (source.value === 'manual' || providers.value.some((item) => item.id === source.value)) ? source.value : ''))
const shown = computed(() => {
  const query = search.value.trim().toLowerCase()
  const list = items.value.filter(
    (item) => (!activeSource.value || (activeSource.value === 'manual' ? !item.source : item.source === activeSource.value)) && (!query || `${item.name} ${item.addr}`.toLowerCase().includes(query))
  )
  if (sort.value === 'name') return [...list].sort((a, b) => a.name.localeCompare(b.name, 'zh-CN'))
  const key = (item: Item) => item.delay ?? Number.POSITIVE_INFINITY
  return [...list].sort((a, b) => key(a) - key(b))
})
const test = (item: Item) => (item.source ? testPoolNode(item.id) : testNode(item.id))

const testingAll = ref(false)
async function testAll() {
  testingAll.value = true
  await limited(shown.value.filter((item) => !item.inactive).map((item) => () => test(item)))
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

// ---- subscriptions -------------------------------------------------------------------
const intervalText = (seconds: number) => (seconds % 86400 === 0 ? `${seconds / 86400} 天` : seconds % 3600 === 0 ? `${seconds / 3600} 小时` : `${seconds} 秒`)
const countOf = (id: string) => poolNodes.value.filter((node) => node.provider_id === id).length
const updatedOf = (id: string) => {
  const at = providerUpdated.value[id]
  return at ? ago(Date.parse(at) / 1000) : '—'
}
const addingProvider = ref(false)
const editingProvider = ref<Provider | null>(null)
const removingProvider = ref<Provider | null>(null)
const providerError = ref('')
const refreshing = ref<Record<string, boolean>>({})

async function refreshProvider(provider: Provider) {
  refreshing.value[provider.id] = true
  try {
    await call(client.POST('/providers/{id}/refresh', { params: { path: { id: provider.id } } }))
  } catch (failure) {
    toast('bad', `${provider.name}：${describe(failure)}`, 5000)
  } finally {
    delete refreshing.value[provider.id]
  }
}
async function refreshAll() {
  await Promise.all(providers.value.map(refreshProvider))
  await loadProviders().catch(() => {})
}
async function refreshOne(provider: Provider) {
  await refreshProvider(provider)
  await loadProviders().catch(() => {})
}
async function removeProvider() {
  const provider = removingProvider.value
  if (!provider) return
  busy.value = true
  providerError.value = ''
  try {
    await call(client.DELETE('/providers/{id}', { params: { path: { id: provider.id } } }))
    toast('ok', `已删除「${provider.name}」`)
    removingProvider.value = null
    await Promise.all([loadProxy().catch(() => {}), loadProviders().catch(() => {})])
  } catch (failure) {
    const groups = failure instanceof ApiError && failure.status === 409 ? (failure.body as { groups?: unknown[] } | undefined)?.groups : undefined
    if (groups?.length) {
      const names = groups.map((group) => (typeof group === 'string' ? nameOf(group) : ((group as { name?: string }).name ?? '')))
      providerError.value = `还被这些组引用：${names.join('、')}`
    } else {
      providerError.value = describe(failure)
    }
  } finally {
    busy.value = false
    refreshStatus().catch(() => {})
  }
}
function closeProvider() {
  addingProvider.value = false
  editingProvider.value = null
}
</script>

<template>
  <div v-if="error" class="err">{{ error }}</div>
  <div class="card">
    <div class="grid g4" style="gap: 8px">
      <div class="tile"><div class="k">总节点</div><div class="big">{{ items.length }}</div></div>
      <div class="tile"><div class="k">正常</div><div class="big" style="color: var(--ok)">{{ stats.ok + stats.warn }}</div></div>
      <div class="tile"><div class="k">失败</div><div class="big" style="color: var(--bad)">{{ stats.bad }}</div></div>
      <div class="tile"><div class="k">未测速</div><div class="big muted">{{ stats.idle }}</div></div>
    </div>
  </div>
  <div v-if="isMihomo" class="card">
    <div class="hd">
      <h2>订阅</h2>
      <span class="tag">{{ providers.length }}</span>
      <span class="sp"></span>
      <button class="btn" type="button" :disabled="!providers.length || Object.keys(refreshing).length > 0" @click="refreshAll">全部更新</button>
      <button class="btn pri" type="button" @click="addingProvider = true">＋ 添加订阅</button>
    </div>
    <div v-if="providers.length" class="tblwrap">
      <table>
        <thead>
          <tr><th>名称</th><th>节点</th><th>筛选</th><th>下载方式</th><th>更新间隔</th><th>最近更新</th><th>状态</th><th style="text-align: right">操作</th></tr>
        </thead>
        <tbody>
          <tr v-for="provider in providers" :key="provider.id">
            <td>{{ provider.name }}</td>
            <td class="tnum">{{ countOf(provider.id) }}</td>
            <td class="mono"><template v-if="provider.filter">{{ provider.filter }}</template><span v-else class="t2">—</span></td>
            <td>{{ provider.download_via ? `经 ${nameOf(provider.download_via)}` : '直连' }}</td>
            <td>{{ intervalText(provider.interval) }}</td>
            <td>{{ updatedOf(provider.id) }}</td>
            <td>
              <span v-if="refreshing[provider.id]" class="pill idle">更新中</span>
              <span v-else class="pill" :class="countOf(provider.id) ? 'ok' : 'warn'"><span class="dot"></span>{{ countOf(provider.id) ? '正常' : '无节点' }}</span>
            </td>
            <td style="text-align: right">
              <button class="ico" type="button" aria-label="立即更新" title="立即更新" :disabled="refreshing[provider.id]" @click="refreshOne(provider)">
                <svg viewBox="0 0 24 24"><path d="M20 11a8 8 0 10-2.3 5.7M20 4v7h-7" /></svg>
              </button>
              <button class="ico" type="button" aria-label="编辑" title="编辑" @click="editingProvider = provider">
                <svg viewBox="0 0 24 24"><path d="M4 20h4L19 9l-4-4L4 16z" /></svg>
              </button>
              <button class="ico" type="button" aria-label="删除" title="删除" style="color: var(--bad)" @click="((removingProvider = provider), (providerError = ''))">
                <svg viewBox="0 0 24 24"><path d="M5 7h14M9 7V4h6v3M7 7l1 13h8l1-13" /></svg>
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
  <div class="card">
    <div class="hd">
      <h2>节点</h2>
      <span class="tag">{{ items.length }}</span>
      <div v-if="isMihomo" class="seg sm" role="group" aria-label="来源">
        <button type="button" :class="{ on: activeSource === '' }" @click="source = ''">全部</button>
        <button type="button" :class="{ on: activeSource === 'manual' }" @click="source = 'manual'">手动</button>
        <button v-for="provider in providers" :key="provider.id" type="button" :class="{ on: activeSource === provider.id }" @click="source = provider.id">{{ provider.name }}</button>
      </div>
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
      <div v-for="item in shown" :key="item.id" class="ncard" :style="item.inactive ? { opacity: 0.6 } : undefined">
        <div class="row">
          <span class="tag">{{ item.type }}</span>
          <span v-if="isMihomo" class="tag" :class="{ acc: item.source }">{{ item.sourceName }}</span>
          <span class="sp"></span>
          <span v-if="item.inactive" class="pill idle" :title="item.inactive">不生效</span>
          <span v-else class="tnum" :style="{ color: `var(--${item.kind === 'idle' ? 'muted' : item.kind})` }">{{ testing[item.id] ? '…' : item.text }}</span>
        </div>
        <div class="nm">{{ item.name }}</div>
        <div v-if="item.inactive" class="t2">{{ item.inactive }}</div>
        <div v-else-if="item.addr" class="t2 mono">{{ item.addr }}</div>
        <div v-if="item.node" class="hint">所在组：{{ item.groups.map(nameOf).join('、') || '无' }}</div>
        <div class="acts">
          <button v-if="item.node" class="ico" type="button" aria-label="复制地址" title="复制地址" @click="copy(item.addr)">
            <svg viewBox="0 0 24 24"><rect x="8" y="8" width="12" height="12" rx="2" /><path d="M4 16V4h12" /></svg>
          </button>
          <button v-if="!item.inactive" class="ico" type="button" aria-label="测速" title="测速" @click="test(item)">
            <svg viewBox="0 0 24 24"><path d="M13 3L5 14h6l-1 7 8-11h-6z" /></svg>
          </button>
          <button v-if="item.node" class="ico" type="button" aria-label="编辑" title="编辑" @click="editing = item.node">
            <svg viewBox="0 0 24 24"><path d="M4 20h4L19 9l-4-4L4 16z" /></svg>
          </button>
          <button v-if="item.node" class="ico" type="button" aria-label="删除" title="删除" style="color: var(--bad)" @click="removing = item.node">
            <svg viewBox="0 0 24 24"><path d="M5 7h14M9 7V4h6v3M7 7l1 13h8l1-13" /></svg>
          </button>
        </div>
      </div>
    </div>
  </div>

  <ProviderModal v-if="addingProvider || editingProvider" :provider="editingProvider ?? undefined" @close="closeProvider" />
  <AppModal v-if="removingProvider" :title="`删除订阅「${removingProvider.name}」`" @close="removingProvider = null">
    <div v-if="providerError" class="err">{{ providerError }}</div>
    <template #footer>
      <button class="btn" type="button" @click="removingProvider = null">取消</button>
      <button class="btn red" type="button" :disabled="busy" @click="removeProvider">删除</button>
    </template>
  </AppModal>
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
