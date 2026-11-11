<script setup lang="ts">
import { computed, ref } from 'vue'
import { RouterLink } from 'vue-router'
import { call, client, describe, type Schemas } from '../api/client'
import DnsTabs from '../components/DnsTabs.vue'
import { usePoll } from '../composables/poll'
import { loadUpstreams, upstreamGroups } from '../composables/rules'

type Rank = Schemas['AuditRankItem'][]
const stats = ref<{ total_queries: number; average_duration_ms: number } | null>(null)
const windows = ref<{ key: string; label: string; request_count: number; average_duration_ms: number }[]>([])
const domains = ref<Rank>([])
const clients = ref<Rank>([])
const sets = ref<Rank>([])
const error = ref('')

async function load() {
  const results = await Promise.allSettled([
    call(client.GET('/audit/stats')),
    call(client.GET('/audit/stats/windows')),
    call(client.GET('/audit/rank/domain', { params: { query: { limit: 8 } } })),
    call(client.GET('/audit/rank/client', { params: { query: { limit: 8 } } })),
    call(client.GET('/audit/rank/domain_set', { params: { query: { limit: 8 } } })),
    loadUpstreams()
  ])
  const [total, recent, topDomains, topClients, topSets] = results
  stats.value = total.status === 'fulfilled' ? total.value : null
  windows.value = recent.status === 'fulfilled' ? recent.value.items : []
  domains.value = topDomains.status === 'fulfilled' ? topDomains.value : []
  clients.value = topClients.status === 'fulfilled' ? topClients.value : []
  sets.value = topSets.status === 'fulfilled' ? topSets.value : []
  const failed = results.find((result) => result.status === 'rejected')
  error.value = failed ? describe((failed as PromiseRejectedResult).reason) : ''
}
usePoll(load, 10000)

const windowOf = (key: string) => windows.value.find((item) => item.key === key)
const ranks = computed(() => [
  { title: '热门域名', items: domains.value, mono: true },
  { title: '活跃客户端', items: clients.value, mono: true },
  { title: '命中分类', items: sets.value, mono: false }
])
const PROTOCOLS: Record<string, string> = { udp: 'UDP', tcp: 'TCP', tls: 'DoT', dot: 'DoT', https: 'DoH', doh: 'DoH' }
</script>

<template>
  <DnsTabs />
  <div v-if="error" class="err">{{ error }}</div>
  <div class="grid g4">
    <div class="card">
      <div class="t2">记录的查询</div>
      <div class="big tnum">{{ stats ? stats.total_queries.toLocaleString() : '—' }}</div>
    </div>
    <div class="card">
      <div class="t2">平均耗时</div>
      <div class="big tnum">{{ stats ? `${stats.average_duration_ms.toFixed(1)} ms` : '—' }}</div>
    </div>
    <div class="card">
      <div class="t2">1 小时内</div>
      <div class="big tnum">{{ windowOf('1h')?.request_count.toLocaleString() ?? '—' }}</div>
    </div>
    <div class="card">
      <div class="t2">24 小时内</div>
      <div class="big tnum">{{ windowOf('24h')?.request_count.toLocaleString() ?? '—' }}</div>
    </div>
  </div>
  <div class="grid g3">
    <div v-for="rank in ranks" :key="rank.title" class="card">
      <div class="hd"><h2>{{ rank.title }}</h2></div>
      <div class="bars">
        <div v-for="item in rank.items" :key="item.key" class="bar">
          <span :class="{ mono: rank.mono }" style="overflow-wrap: anywhere">{{ item.key }}</span>
          <span class="tnum t2">{{ item.count.toLocaleString() }}</span>
          <span class="tr"><i :style="{ width: `${(item.count / (rank.items[0]?.count || 1)) * 100}%` }"></i></span>
        </div>
        <div v-if="!rank.items.length" class="t2">—</div>
      </div>
    </div>
  </div>
  <div class="card">
    <div class="hd">
      <h2>上游</h2>
      <span class="sp"></span>
      <RouterLink class="btn sm ghost" to="/dns/upstreams">编辑上游 →</RouterLink>
    </div>
    <div class="tblwrap">
      <table>
        <thead>
          <tr><th>组</th><th>名称</th><th>协议</th><th>地址</th><th>走代理</th><th>状态</th></tr>
        </thead>
        <tbody>
          <template v-for="group in upstreamGroups" :key="group.tag">
            <tr v-for="upstream in group.upstreams" :key="`${group.tag}:${upstream.tag}`">
              <td>{{ group.name }}</td>
              <td class="mono">{{ upstream.tag }}</td>
              <td>{{ PROTOCOLS[upstream.protocol] ?? upstream.protocol }}</td>
              <td class="mono">{{ upstream.addr }}</td>
              <td>{{ upstream.use_proxy ? '是' : '否' }}</td>
              <td><span class="pill" :class="upstream.enabled === false ? 'idle' : 'ok'">{{ upstream.enabled === false ? '停用' : '启用' }}</span></td>
            </tr>
          </template>
        </tbody>
      </table>
    </div>
  </div>
</template>
