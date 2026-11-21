<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { RouterLink } from 'vue-router'
import { call, client, describe } from '../api/client'
import TrafficChart from '../components/TrafficChart.vue'
import { active as activeConns, failure as connFailure, sample as sampleConnections, totals as connTotals } from '../composables/connections'
import { ms } from '../composables/dnslog'
import {
  SYSTEM_SAMPLES,
  cacheHit,
  cachedTotals,
  cpuHistory,
  dnsStats,
  fetchSystem,
  liveTraffic,
  loadOverviewState,
  memHistory,
  overviewDns,
  overviewGroups,
  overviewNodes,
  overviewOrder,
  overviewRules,
  overviewSettings,
  selectTrafficWindow,
  shares,
  syncConnectionTotals,
  system,
  trafficSeries,
  trafficWindow
} from '../composables/overview'
import { usePoll } from '../composables/poll'
import { isPoolNode, poolNodes, runtime } from '../composables/proxy'
import { sparkArea, sparkLine } from '../composables/spark'
import { backendName, refreshStatus, status } from '../composables/status'
import { toast } from '../composables/toast'
import { ago, bytes, duration, latency, latencyText, rate, triggers } from '../format'
import { aggregateTraffic, type BreakdownDim, type TrafficWindow } from '../overviewHelpers'

const WINDOWS: Array<{ key: TrafficWindow; label: string }> = [
  { key: '3m', label: '3 分钟' },
  { key: '15m', label: '15 分钟' },
  { key: '1h', label: '1 小时' }
]
const DIMS: Array<{ key: BreakdownDim; label: string }> = [
  { key: 'group', label: '按分组' },
  { key: 'client', label: '按设备' },
  { key: 'host', label: '按主机' }
]

const breakdownDim = ref<BreakdownDim>('group')
const connSampled = ref(false)
let pollTicks = 0
let warmupTimer: ReturnType<typeof setTimeout> | undefined
let mounted = true

async function pollTelemetry() {
  const tick = pollTicks++
  const needHistory = tick === 0 || (trafficWindow.value !== '3m' && tick % 5 === 0)
  const [sysResult] = await Promise.allSettled([
    fetchSystem(needHistory),
    sampleConnections().then(() => {
      if (!connFailure.value) {
        connSampled.value = true
        syncConnectionTotals(
          connTotals.value.down,
          connTotals.value.up,
          connTotals.value.downRate,
          connTotals.value.upRate
        )
      }
    })
  ])
  if (tick === 0 && sysResult.status === 'fulfilled' && sysResult.value && mounted) {
    clearTimeout(warmupTimer)
    warmupTimer = setTimeout(() => {
      if (mounted && !document.hidden) void fetchSystem(false).catch(() => {})
    }, 600)
  }
}

onMounted(() => {
  mounted = true
})
onUnmounted(() => {
  mounted = false
  clearTimeout(warmupTimer)
})

usePoll(pollTelemetry, 2000)
usePoll(loadOverviewState, 10000)

async function pickWindow(win: TrafficWindow) {
  try {
    await selectTrafficWindow(win)
  } catch {
    // Keep existing chart on transient network errors.
  }
}

// ---- Names & group resolution --------------------------------------------------------
const names = computed(() => {
  const map = new Map<string, string>([
    ['final', '兜底分组'],
    ['direct', '直连'],
    ['block', '拒绝']
  ])
  for (const node of overviewNodes.value) map.set(node.id, node.name)
  for (const node of poolNodes.value) map.set(node.id, node.name)
  for (const group of overviewGroups.value) map.set(group.id, group.name)
  return map
})
const nameOf = (id: string | undefined) => (id ? (names.value.get(id) ?? id) : '—')

function endNode(id: string | undefined): string | undefined {
  const seen = new Set<string>()
  let current = id
  while (current && runtime.value?.groups[current] && !seen.has(current)) {
    seen.add(current)
    current = runtime.value.groups[current].now
  }
  return current
}

type PoolNode = (typeof poolNodes.value)[number]
const poolTest = (node: PoolNode) =>
  node.alive === false ? { delay: null, time: 'failed' } : { delay: node.delay ?? null, time: null }
const poolById = computed(() => new Map(poolNodes.value.map((node) => [node.id, node])))

function delayOf(id: string | undefined) {
  if (!id) return undefined
  if (isPoolNode(id)) {
    const node = poolById.value.get(id)
    return node ? poolTest(node) : undefined
  }
  return runtime.value?.nodes[id]
}

const nodeStats = computed(() => {
  const stats = { ok: 0, warn: 0, bad: 0, idle: 0 }
  for (const node of overviewNodes.value) {
    const test = runtime.value?.nodes[node.id]
    stats[latency(test?.delay, test?.time)]++
  }
  for (const node of poolNodes.value) {
    const test = poolTest(node)
    stats[latency(test.delay, test.time)]++
  }
  return stats
})

const shownGroups = computed(() =>
  overviewOrder.value.slice(0, 4).map((id) => {
    const now = runtime.value?.groups[id]?.now
    const test = delayOf(endNode(id))
    return {
      id,
      name: nameOf(id),
      now,
      kind: latency(test?.delay, test?.time),
      text: latencyText(test?.delay, test?.time)
    }
  })
)

// ---- Traffic KPIs & breakdown --------------------------------------------------------
const currentDownRate = computed(() => {
  if (liveTraffic.value) return liveTraffic.value.down
  if (connSampled.value) return connTotals.value.downRate
  return null
})
const currentUpRate = computed(() => {
  if (liveTraffic.value) return liveTraffic.value.up
  if (connSampled.value) return connTotals.value.upRate
  return null
})
const peakDownRate = computed(() => {
  let peak = currentDownRate.value ?? 0
  for (const point of trafficSeries.value) if (point.down > peak) peak = point.down
  return peak
})
const peakUpRate = computed(() => {
  let peak = currentUpRate.value ?? 0
  for (const point of trafficSeries.value) if (point.up > peak) peak = point.up
  return peak
})
const totalDown = computed(() => (connSampled.value ? connTotals.value.down : (cachedTotals.value?.down ?? null)))
const totalUp = computed(() => (connSampled.value ? connTotals.value.up : (cachedTotals.value?.up ?? null)))

const breakdown = computed(() => aggregateTraffic(activeConns.value, breakdownDim.value, nameOf, 5))
const breakdownMax = computed(() => {
  const items = breakdown.value.items
  if (!items.length) return 1
  return Math.max(1, ...items.map((item) => (breakdown.value.byRate ? item.rate : item.total)))
})
const barWidth = (value: number) => `${Math.max(4, Math.round((value / breakdownMax.value) * 100))}%`

// ---- System & DNS summaries ----------------------------------------------------------
const enabledRules = computed(() => overviewRules.value?.rules.filter((rule) => rule.enabled).length ?? 0)
const uptime = computed(() => {
  const started = system.value?.atomdns?.start_time_seconds
  return started ? duration(Date.now() / 1000 - started) : ''
})
const lastApply = computed(() => status.value?.last_apply ?? null)
const emptyGroups = computed(() => (status.value?.warnings.empty_groups ?? []).map(nameOf))

const topMeta = computed(() => {
  const parts: string[] = []
  if (uptime.value) parts.push(`DNS ${uptime.value}`)
  if (status.value) parts.push(backendName.value)
  if (lastApply.value) parts.push(`最近应用 ${ago(lastApply.value.at)}`)
  return parts.join(' · ')
})

const alerts = computed(() => {
  const list: string[] = []
  if (status.value && !status.value.singbox.running) list.push(`${backendName.value} 未运行`)
  else if (status.value && !status.value.singbox.in_sync) list.push(`${backendName.value} 配置未同步`)
  if (lastApply.value && !lastApply.value.ok) {
    const trig = triggers[lastApply.value.trigger] ?? lastApply.value.trigger
    const detail = lastApply.value.error ? `：${lastApply.value.error}` : ''
    list.push(`最近一次应用失败（${ago(lastApply.value.at)} · ${trig}）${detail}`)
  }
  if (emptyGroups.value.length) list.push(`空节点组：${emptyGroups.value.join('、')}`)
  return list
})

const cpuSparkMax = computed(() => {
  let peak = 0
  for (const val of cpuHistory.value) if (val > peak) peak = val
  return Math.min(100, Math.max(25, peak * 1.4))
})
const latestCpu = computed(() => (cpuHistory.value.length ? cpuHistory.value[cpuHistory.value.length - 1] : null))
const latestMem = computed(() => (memHistory.value.length ? memHistory.value[memHistory.value.length - 1] : null))
const memPct = computed(() => {
  const total = system.value?.memory?.total_bytes
  if (!total || latestMem.value === null) return ''
  return `${((latestMem.value / total) * 100).toFixed(1)}%`
})
const sysMeta = computed(() => {
  const parts: string[] = []
  if (system.value?.cpu) parts.push(`${system.value.cpu.cores} 核`)
  const load1 = system.value?.load?.[0]
  if (typeof load1 === 'number' && Number.isFinite(load1)) parts.push(`负载 ${load1.toFixed(2)}`)
  return parts.join(' · ')
})
const cpuProcText = computed(() => {
  const parts: string[] = []
  if (shares.value.atomdns != null) parts.push(`atomdns ${shares.value.atomdns.toFixed(1)}%`)
  if (shares.value.singbox != null) parts.push(`${backendName.value} ${shares.value.singbox.toFixed(1)}%`)
  return parts.join(' · ')
})
const memProcText = computed(() => {
  const parts: string[] = []
  if (system.value?.atomdns) parts.push(`atomdns ${bytes(system.value.atomdns.resident_bytes)}`)
  if (system.value?.singbox) parts.push(`${backendName.value} ${bytes(system.value.singbox.resident_bytes)}`)
  return parts.join(' · ')
})

const applying = ref(false)
async function reapply() {
  applying.value = true
  try {
    await call(client.POST('/apply'))
    toast('ok', `已重新应用到 ${backendName.value}`)
  } catch (error) {
    toast('bad', describe(error))
  } finally {
    applying.value = false
    refreshStatus().catch(() => {})
  }
}
</script>

<template>
  <Teleport to="#top-actions" defer>
    <span v-if="topMeta" class="t2 tnum ov-top-meta">{{ topMeta }}</span>
    <button class="btn sm" :disabled="applying" @click="reapply">重新应用</button>
  </Teleport>

  <div v-if="alerts.length" class="ov-alert">
    <span class="dot"></span>
    <span>{{ alerts.join('；') }}</span>
    <span class="sp"></span>
    <button class="btn sm" :disabled="applying" @click="reapply">立即重新应用</button>
  </div>

  <!-- Row 1 (HERO): Network Traffic (2fr) + Live Breakdown (1fr) -->
  <section class="ov-hero">
    <div class="card ov-hero-card">
      <div class="hd" style="margin-bottom: 0">
        <h2>网络流量</h2>
        <span class="sp"></span>
        <div class="seg sm" role="tablist" aria-label="流量时间窗口">
          <button
            v-for="item in WINDOWS"
            :key="item.key"
            type="button"
            :class="{ on: trafficWindow === item.key }"
            @click="pickWindow(item.key)"
          >
            {{ item.label }}
          </button>
        </div>
        <RouterLink class="btn sm ghost" to="/connections">实时连接 →</RouterLink>
      </div>

      <div class="ov-kpi">
        <div class="tile">
          <div class="k"><span class="dot" style="color: var(--accent)"></span>下行速率</div>
          <div class="ov-big tnum">{{ currentDownRate !== null ? rate(currentDownRate) : '—' }}</div>
          <div class="s tnum">{{ trafficSeries.length ? `峰值 ${rate(peakDownRate)}` : '—' }}</div>
        </div>
        <div class="tile">
          <div class="k"><span class="dot" style="color: var(--ok)"></span>上行速率</div>
          <div class="ov-big tnum">{{ currentUpRate !== null ? rate(currentUpRate) : '—' }}</div>
          <div class="s tnum">{{ trafficSeries.length ? `峰值 ${rate(peakUpRate)}` : '—' }}</div>
        </div>
        <div class="tile">
          <div class="k">本次运行累计</div>
          <div class="v tnum" style="margin-top: 6px">{{ totalDown !== null ? `↓ ${bytes(totalDown)}` : '—' }}</div>
          <div class="s tnum">{{ totalUp !== null ? `↑ ${bytes(totalUp)}` : '—' }}</div>
        </div>
        <div class="tile">
          <div class="k">活跃连接</div>
          <div class="ov-big tnum">{{ connSampled ? activeConns.length : '—' }}</div>
          <div class="s tnum">
            <template v-if="connSampled">
              {{ breakdown.clients }} 台设备 · TCP {{ breakdown.tcp }} / UDP {{ breakdown.udp }}
            </template>
            <template v-else>—</template>
          </div>
        </div>
      </div>

      <TrafficChart :series="trafficSeries" :window="trafficWindow" />
    </div>

    <div class="card ov-side-card">
      <div class="hd" style="margin-bottom: 0">
        <h2>流量分布</h2>
        <span class="sp"></span>
        <div class="seg sm" role="tablist" aria-label="流量分布维度">
          <button
            v-for="item in DIMS"
            :key="item.key"
            type="button"
            :class="{ on: breakdownDim === item.key }"
            @click="breakdownDim = item.key"
          >
            {{ item.label }}
          </button>
        </div>
      </div>

      <div v-if="breakdown.items.length" class="ov-bars">
        <div v-for="item in breakdown.items" :key="item.key" class="ov-bar-item">
          <div class="ov-bar-top">
            <div class="ov-bar-name">
              <span>{{ item.name }}</span>
              <span v-if="item.sub" class="t2"> {{ item.sub }}</span>
            </div>
            <div class="ov-bar-val tnum">
              <span v-if="breakdown.byRate">{{ rate(item.rate) }}</span>
              <span :class="breakdown.byRate ? 't2' : ''">{{ breakdown.byRate ? ` ${bytes(item.total)}` : bytes(item.total) }}</span>
            </div>
          </div>
          <div class="ov-bar-tr">
            <i :style="{ width: barWidth(breakdown.byRate ? item.rate : item.total), background: item.color }"></i>
          </div>
        </div>
      </div>
      <div v-else class="ov-empty t2">当前暂无活跃连接</div>

      <div class="ov-card-foot">
        <span>{{ breakdown.byRate ? '按当前实时速率排序' : '按累计流量排序' }}</span>
        <span v-if="breakdown.proxyShare !== null && breakdown.directShare !== null" class="tnum">
          代理 {{ breakdown.proxyShare }}% · 直连 {{ breakdown.directShare }}%
        </span>
      </div>
    </div>
  </section>

  <!-- Row 2: 3 Balanced Pillar Cards -->
  <section class="ov-pillars">
    <!-- Pillar 1: Proxy Groups & Nodes -->
    <div class="card ov-pillar">
      <div class="hd" style="margin-bottom: 0">
        <h2>出口与节点</h2>
        <span class="sp"></span>
        <RouterLink class="btn sm ghost" to="/groups">节点组 →</RouterLink>
        <RouterLink class="btn sm ghost" to="/nodes">节点 →</RouterLink>
      </div>
      <div class="ov-node-summary">
        <div class="row" style="gap: 6px; align-items: baseline">
          <span class="ov-mid tnum">{{ overviewNodes.length + poolNodes.length }}</span>
          <span class="t2">节点</span>
        </div>
        <div v-if="!runtime" class="t2">延迟不可用</div>
        <div v-else class="row" style="gap: 5px">
          <span class="pill ok">正常 {{ nodeStats.ok }}</span>
          <span class="pill warn">偏高 {{ nodeStats.warn }}</span>
          <span class="pill bad">失败 {{ nodeStats.bad }}</span>
          <span class="pill idle">未测 {{ nodeStats.idle }}</span>
        </div>
      </div>
      <div class="ov-group-list">
        <div v-for="group in shownGroups" :key="group.id" class="ov-group-row">
          <span class="ov-group-name">{{ group.name }}</span>
          <span class="ov-group-now">→ {{ nameOf(group.now) }}</span>
          <span class="sp"></span>
          <span class="pill tnum" :class="group.kind">{{ group.text }}</span>
        </div>
        <div v-if="!shownGroups.length" class="ov-empty t2">暂无节点组</div>
      </div>
    </div>

    <!-- Pillar 2: DNS & Routing -->
    <div class="card ov-pillar">
      <div class="hd" style="margin-bottom: 0">
        <h2>DNS 与分流</h2>
        <span class="sp"></span>
        <RouterLink class="btn sm ghost" to="/dns">DNS 详情 →</RouterLink>
      </div>
      <div class="ov-dns-grid">
        <div class="tile ov-dns-tile">
          <div class="k">DNS 查询</div>
          <div class="ov-mid tnum">{{ dnsStats ? dnsStats.totalQueries.toLocaleString() : '—' }}</div>
          <div class="s tnum">{{ dnsStats ? `平均 ${ms(dnsStats.avgDurationMs)}` : '—' }}</div>
        </div>
        <div class="tile ov-dns-tile">
          <div class="k">缓存命中</div>
          <div class="ov-mid tnum">{{ cacheHit ?? '—' }}</div>
          <div class="s">{{ overviewDns ? (overviewDns.core_mode === 'safe' ? '安全模式' : '兼容模式') : '—' }}</div>
        </div>
        <div class="tile ov-dns-tile">
          <div class="k">分流规则</div>
          <div class="ov-mid tnum">
            <template v-if="overviewRules">{{ enabledRules }} <span class="t2">/ {{ overviewRules.rules.length }}</span></template>
            <template v-else>—</template>
          </div>
          <div class="s">已启用</div>
        </div>
        <div class="tile ov-dns-tile">
          <div class="k">绑定账本</div>
          <div class="ov-mid tnum">{{ status ? (status.bindings.size ?? 0).toLocaleString() : '—' }}</div>
          <div class="s tnum">{{ status ? `上限 ${(status.bindings.capacity ?? 0).toLocaleString()}` : '—' }}</div>
        </div>
      </div>
      <div class="ov-card-foot mono">
        <span>FakeIP {{ overviewSettings?.fakeip_range ?? '—' }}</span>
        <span>Mixed {{ overviewSettings?.mixed_port ? `:${overviewSettings.mixed_port}` : '—' }}</span>
      </div>
    </div>

    <!-- Pillar 3: Condensed Cached System Resources -->
    <div class="card ov-pillar">
      <div class="hd" style="margin-bottom: 0">
        <h2>系统资源</h2>
        <span class="sp"></span>
        <span v-if="sysMeta" class="t2 tnum">{{ sysMeta }}</span>
      </div>

      <div class="ov-sys-box">
        <div class="ov-sys-top">
          <span class="t2">CPU 使用率</span>
          <span class="ov-mid tnum">{{ system?.cpu && latestCpu !== null ? `${latestCpu.toFixed(1)}%` : '—' }}</span>
        </div>
        <svg class="ov-mini-spark" viewBox="0 0 260 38" preserveAspectRatio="none">
          <polygon :points="sparkArea(cpuHistory, cpuSparkMax, 260, 38, SYSTEM_SAMPLES)" fill="var(--accent-soft)" />
          <polyline
            :points="sparkLine(cpuHistory, cpuSparkMax, 260, 38, SYSTEM_SAMPLES)"
            fill="none"
            stroke="var(--accent)"
            stroke-width="1.6"
            vector-effect="non-scaling-stroke"
          />
        </svg>
        <div class="ov-sys-foot tnum">
          <span>{{ cpuProcText || '—' }}</span>
          <span>整机</span>
        </div>
      </div>

      <div class="ov-sys-box">
        <div class="ov-sys-top">
          <span class="t2">内存占用</span>
          <div class="tnum">
            <span class="ov-mid">{{ system?.memory && latestMem !== null ? bytes(latestMem) : '—' }}</span>
            <span v-if="system?.memory" class="t2"> / {{ bytes(system.memory.total_bytes) }}</span>
          </div>
        </div>
        <svg class="ov-mini-spark" viewBox="0 0 260 38" preserveAspectRatio="none">
          <polygon :points="sparkArea(memHistory, system?.memory?.total_bytes ?? 1, 260, 38, SYSTEM_SAMPLES)" fill="var(--ok-soft)" />
          <polyline
            :points="sparkLine(memHistory, system?.memory?.total_bytes ?? 1, 260, 38, SYSTEM_SAMPLES)"
            fill="none"
            stroke="var(--ok)"
            stroke-width="1.6"
            vector-effect="non-scaling-stroke"
          />
        </svg>
        <div class="ov-sys-foot tnum">
          <span>{{ memProcText || '—' }}</span>
          <span>{{ memPct || '整机' }}</span>
        </div>
      </div>
    </div>
  </section>
</template>
