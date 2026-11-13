<script setup lang="ts">
import { computed, ref } from 'vue'
import { call, client, describe, type Schemas } from '../api/client'
import AppModal from '../components/AppModal.vue'
import DnsTabs from '../components/DnsTabs.vue'
import LogDetail from '../components/LogDetail.vue'
import LogList from '../components/LogList.vue'
import { usePoll } from '../composables/poll'
import { loadRules, loadUpstreams, upstreamGroups } from '../composables/rules'
import { FAKEIP_GROUP, groupLabel, ms, tagLabel, type AuditLog } from '../composables/dnslog'

type Rank = Schemas['AuditRankItem'][]
type Stats = { groups: { tag: string; upstreams: Schemas['UpstreamStats'][] }[] }
const RANK_ROWS = 8
const stats = ref<{ total_queries: number; average_duration_ms: number } | null>(null)
const distinct = ref<number | null>(null)
const domains = ref<Rank>([])
const clients = ref<Rank>([])
const slowest = ref<AuditLog[]>([])
const sets = ref<Rank>([])
const caches = ref<Schemas['Cache'][]>([])
const upstreamStats = ref<Stats['groups']>([])
const error = ref('')

/** The top names and the number of distinct names (a header of the same answer). */
async function loadDomains() {
  const { data, error: failure, response } = await client.GET('/audit/rank/domain', { params: { query: { limit: RANK_ROWS } } })
  if (!response.ok || failure !== undefined || !data) throw new Error((failure as { error?: string } | undefined)?.error || `请求失败（${response.status}）`)
  domains.value = data
  const header = Number(response.headers.get('X-Audit-Distinct-Domains'))
  distinct.value = Number.isFinite(header) ? header : null
}

/** The rankings one at a time: the server runs two audit reads at once and answers 503 to more. */
async function loadRanks() {
  const steps = [
    loadDomains,
    async () => (clients.value = await call(client.GET('/audit/rank/client', { params: { query: { limit: RANK_ROWS } } }))),
    async () => (slowest.value = await call(client.GET('/audit/rank/slowest', { params: { query: { limit: RANK_ROWS } } }))),
    async () => (sets.value = await call(client.GET('/audit/rank/domain_set', { params: { query: { limit: 500 } } })))
  ]
  let failure: unknown = null
  for (const step of steps) {
    try {
      await step()
    } catch (reason) {
      failure ??= reason
    }
  }
  if (failure !== null) throw failure
}

async function load() {
  const results = await Promise.allSettled([
    call(client.GET('/audit/stats')).then((value) => (stats.value = value)),
    loadRanks(),
    call(client.GET('/caches')).then((value) => (caches.value = value.caches)),
    call(client.GET('/stats/upstreams')).then((value) => (upstreamStats.value = value.groups)),
    loadUpstreams(),
    loadRules()
  ])
  const failed = results.find((result) => result.status === 'rejected')
  error.value = failed ? describe((failed as PromiseRejectedResult).reason) : ''
}
usePoll(load, 10000)

const percent = (part: number, whole: number) => (whole > 0 ? `${((part / whole) * 100).toFixed(1)}%` : '—')

// Lookups answered from a cache over all lookups, every cache summed (as AtomDNS's own overview).
const cacheHit = computed(() => {
  const queries = caches.value.reduce((sum, item) => sum + item.queries, 0)
  const hits = caches.value.reduce((sum, item) => sum + item.hits, 0)
  return queries ? percent(hits, queries) : '—'
})

const cards = computed(() => [
  ['查询数量', stats.value ? stats.value.total_queries.toLocaleString() : '—'],
  ['平均响应', stats.value ? ms(stats.value.average_duration_ms) : '—'],
  ['缓存命中', cacheHit.value],
  ['域名统计', distinct.value === null ? '—' : distinct.value.toLocaleString()]
])

// Groups in the order `upstreams` lists them, the FakeIP group last; only upstreams that exist now.
const sections = computed(() => {
  const order = [...upstreamGroups.value.map((group) => group.tag), FAKEIP_GROUP]
  return [...upstreamStats.value]
    .filter((group) => order.includes(group.tag) && group.upstreams.length)
    .sort((a, b) => order.indexOf(a.tag) - order.indexOf(b.tag))
    .map((group) => ({
      tag: group.tag,
      name: groupLabel(group.tag),
      rows: group.upstreams.map((item) => ({
        tag: item.tag,
        queries: item.queries,
        adopted: percent(item.winners, item.queries),
        errors: percent(item.errors, item.queries),
        bad: item.queries > 0 && item.errors / item.queries >= 0.2,
        latency: item.latency_count ? ms(item.latency_sum_ms / item.latency_count) : '—'
      }))
    }))
})

// The rule share ring: the five largest, the rest as one slice (r = 50 on a 120 box).
const SLICES = 5
const OTHER = '\u0000other'
const CIRCLE = 2 * Math.PI * 50
const ring = computed(() => {
  const total = sets.value.reduce((sum, item) => sum + item.count, 0)
  const top = sets.value.slice(0, SLICES).map((item) => ({ key: item.key, label: tagLabel(item.key), count: item.count }))
  const rest = sets.value.slice(SLICES).reduce((sum, item) => sum + item.count, 0)
  if (rest) top.push({ key: OTHER, label: '其他', count: rest })
  let offset = 0
  const slices = top.map((slice, index) => {
    const length = total ? (slice.count / total) * CIRCLE : 0
    const item = { ...slice, color: `var(--c${index + 1})`, dash: `${length} ${CIRCLE - length}`, offset: -offset, share: percent(slice.count, total) }
    offset += length
    return item
  })
  return { total, slices }
})

const ranks = computed(() => [
  { title: '热门域名', kind: 'domain' as const, items: domains.value },
  { title: '活跃客户端', kind: 'client' as const, items: clients.value }
])
const width = (value: number, top: number) => `${top ? Math.max(2, (value / top) * 100) : 0}%`

const list = ref<{ title: string; filter: Record<string, string>; count: number } | null>(null)
const opened = ref<AuditLog | null>(null)
// "其他": the categories past the five, each opening its queries.
const othersOpen = ref(false)
const others = computed(() => sets.value.slice(SLICES))
function openSlice(slice: { key: string; count: number }) {
  if (slice.key === OTHER) othersOpen.value = true
  else openRank('set', slice)
}
function openOther(item: { key: string; count: number }) {
  othersOpen.value = false
  openRank('set', item)
}
function openRank(kind: 'domain' | 'client' | 'set', item: { key: string; count: number }) {
  if (kind === 'domain') list.value = { title: `域名 ${item.key}`, filter: { domain: item.key }, count: item.count }
  else if (kind === 'client') list.value = { title: `客户端 ${item.key}`, filter: { client_ip: item.key }, count: item.count }
  else list.value = { title: tagLabel(item.key), filter: { domain_set: item.key }, count: item.count }
}
</script>

<template>
  <DnsTabs />
  <div v-if="error" class="err">{{ error }}</div>
  <div class="grid g4">
    <div v-for="card in cards" :key="card[0]" class="card">
      <div class="t2">{{ card[0] }}</div>
      <div class="big tnum">{{ card[1] }}</div>
    </div>
  </div>
  <div class="split3">
    <div class="card">
      <div class="hd"><h2>上游统计</h2></div>
      <div class="tblwrap">
        <table>
          <thead>
            <tr><th>上游</th><th class="num">请求数</th><th class="num">采纳率</th><th class="num">出错率</th><th class="num">平均延迟</th></tr>
          </thead>
          <tbody>
            <template v-for="section in sections" :key="section.tag">
              <tr class="grp"><td colspan="5">{{ section.name }}</td></tr>
              <tr v-for="row in section.rows" :key="`${section.tag}:${row.tag}`">
                <td>{{ row.tag }}</td>
                <td class="num tnum">{{ row.queries.toLocaleString() }}</td>
                <td class="num tnum">{{ row.adopted }}</td>
                <td class="num tnum" :class="{ bad: row.bad }">{{ row.errors }}</td>
                <td class="num tnum">{{ row.latency }}</td>
              </tr>
            </template>
            <tr v-if="!sections.length"><td colspan="5" class="t2">—</td></tr>
          </tbody>
        </table>
      </div>
    </div>
    <div class="card">
      <div class="hd"><h2>分流状态</h2></div>
      <div class="ring">
        <svg viewBox="0 0 120 120" role="img" aria-label="规则命中占比">
          <circle cx="60" cy="60" r="50" fill="none" stroke="var(--fill)" stroke-width="16" />
          <circle
            v-for="slice in ring.slices"
            :key="slice.label"
            cx="60"
            cy="60"
            r="50"
            fill="none"
            :stroke="slice.color"
            stroke-width="16"
            :stroke-dasharray="slice.dash"
            :stroke-dashoffset="slice.offset"
            transform="rotate(-90 60 60)"
          />
          <text x="60" y="58" text-anchor="middle" class="ring-n">{{ ring.total.toLocaleString() }}</text>
          <text x="60" y="74" text-anchor="middle" class="ring-k">次查询</text>
        </svg>
      </div>
      <div class="legend">
        <button v-for="slice in ring.slices" :key="slice.label" class="lg" type="button" @click="openSlice(slice)">
          <i :style="{ background: slice.color }"></i>
          <span class="nm">{{ slice.label }}</span>
          <span class="tnum t2">{{ slice.share }}</span>
        </button>
        <div v-if="!ring.slices.length" class="t2">—</div>
      </div>
    </div>
  </div>
  <div class="grid g3">
    <div v-for="rank in ranks" :key="rank.title" class="card">
      <div class="hd"><h2>{{ rank.title }}</h2></div>
      <div class="bars">
        <button v-for="item in rank.items" :key="item.key" class="bar pick" type="button" @click="openRank(rank.kind, item)">
          <span class="mono nm">{{ item.key }}</span>
          <span class="tnum t2">{{ item.count.toLocaleString() }}</span>
          <span class="tr"><i :style="{ width: width(item.count, rank.items[0]?.count ?? 0) }"></i></span>
        </button>
        <div v-if="!rank.items.length" class="t2">—</div>
      </div>
    </div>
    <div class="card">
      <div class="hd"><h2>最慢查询</h2></div>
      <div class="bars">
        <button v-for="log in slowest" :key="log.trace_id" class="bar pick" type="button" @click="opened = log">
          <span class="mono nm">{{ log.query_name }}</span>
          <span class="tnum t2">{{ ms(log.duration_ms) }}</span>
          <span class="tr"><i :style="{ width: width(log.duration_ms, slowest[0]?.duration_ms ?? 0) }"></i></span>
        </button>
        <div v-if="!slowest.length" class="t2">—</div>
      </div>
    </div>
  </div>
  <LogList v-if="list" :title="list.title" :filter="list.filter" :count="list.count" :total="stats?.total_queries ?? 0" @close="list = null" />
  <LogDetail v-if="opened" :log="opened" @close="opened = null" />
  <AppModal v-if="othersOpen" title="其他" @close="othersOpen = false">
    <div class="legend">
      <button v-for="item in others" :key="item.key" class="lg" type="button" @click="openOther(item)">
        <span class="nm">{{ tagLabel(item.key) }}</span>
        <span class="tnum t2">{{ item.count.toLocaleString() }} · {{ percent(item.count, ring.total) }}</span>
      </button>
    </div>
    <template #footer>
      <button class="btn" type="button" @click="othersOpen = false">关闭</button>
    </template>
  </AppModal>
</template>
