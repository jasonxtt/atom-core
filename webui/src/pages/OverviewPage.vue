<script setup lang="ts">
import { computed, ref } from 'vue'
import { RouterLink } from 'vue-router'
import { call, client, describe, type Schemas } from '../api/client'
import { usePoll } from '../composables/poll'
import { refreshStatus, singboxVersion, status } from '../composables/status'
import { sparkArea, sparkLine } from '../composables/spark'
import { toast } from '../composables/toast'
import { ago, bytes, duration, latency, latencyText, rate, triggers } from '../format'

type Runtime = { groups: Record<string, { now: string }>; nodes: Record<string, { delay: number | null; time: string | null }> }

const SAMPLES = 60
const cpu = ref<number[]>([])
const memory = ref<number[]>([])
const system = ref<Schemas['System'] | null>(null)
const shares = ref<{ atomdns: number | null; singbox: number | null }>({ atomdns: null, singbox: null })
let previous: Schemas['System'] | null = null

function push(list: number[], value: number) {
  list.push(value)
  if (list.length > SAMPLES) list.shift()
}

// CPU use between two samples: the machine's busy share, and each process's CPU time over the
// same total (so the three figures add up on one scale).
// A failed sample shows the figures as unavailable (the curves keep what was sampled).
async function sampleSystem() {
  let now: Schemas['System']
  try {
    now = await call(client.GET('/system'))
  } catch (error) {
    system.value = null
    previous = null
    shares.value = { atomdns: null, singbox: null }
    throw error
  }
  if (!now.cpu) shares.value = { atomdns: null, singbox: null }
  if (previous?.cpu && now.cpu) {
    const total = now.cpu.total_seconds - previous.cpu.total_seconds
    if (total > 0) {
      push(cpu.value, ((now.cpu.busy_seconds - previous.cpu.busy_seconds) / total) * 100)
      const share = (key: 'atomdns' | 'singbox') => {
        const a = previous?.[key]
        const b = now[key]
        return a && b && a.pid === b.pid ? ((b.cpu_seconds - a.cpu_seconds) / total) * 100 : null
      }
      shares.value = { atomdns: share('atomdns'), singbox: share('singbox') }
    }
  }
  if (now.memory) push(memory.value, now.memory.total_bytes - now.memory.available_bytes)
  previous = now
  system.value = now
}

const runtime = ref<Runtime | null>(null)
const nodes = ref<Schemas['Node'][]>([])
const groups = ref<Schemas['Group'][]>([])
const order = ref<string[]>([])
const rules = ref<Schemas['RuleTable'] | null>(null)
const settings = ref<Schemas['Settings'] | null>(null)
const dns = ref<Schemas['Dns'] | null>(null)
const traffic = ref<{ count: number; down: number; up: number } | null>(null)
let lastTotals: { at: number; down: number; up: number } | null = null

async function sampleConnections() {
  let snapshot
  try {
    snapshot = await call(client.GET('/connections'))
  } catch (error) {
    traffic.value = null
    lastTotals = null
    throw error
  }
  const at = Date.now()
  const down = snapshot.downloadTotal ?? 0
  const up = snapshot.uploadTotal ?? 0
  const seconds = lastTotals ? (at - lastTotals.at) / 1000 : 0
  traffic.value = {
    count: snapshot.connections?.length ?? 0,
    down: lastTotals && seconds > 0 ? Math.max(0, down - lastTotals.down) / seconds : 0,
    up: lastTotals && seconds > 0 ? Math.max(0, up - lastTotals.up) / seconds : 0
  }
  lastTotals = { at, down, up }
}

async function loadState() {
  const [nodeList, groupList, ruleTable, settingsNow, dnsNow, runtimeNow] = await Promise.allSettled([
    call(client.GET('/nodes')),
    call(client.GET('/groups')),
    call(client.GET('/rules')),
    call(client.GET('/settings')),
    call(client.GET('/dns')),
    call(client.GET('/runtime'))
  ])
  if (nodeList.status === 'fulfilled') nodes.value = nodeList.value.nodes
  if (groupList.status === 'fulfilled') {
    groups.value = groupList.value.groups
    order.value = groupList.value.order
  }
  if (ruleTable.status === 'fulfilled') rules.value = ruleTable.value
  if (settingsNow.status === 'fulfilled') settings.value = settingsNow.value
  if (dnsNow.status === 'fulfilled') dns.value = dnsNow.value
  // 409: sing-box has no configuration yet; nothing to show.
  runtime.value = runtimeNow.status === 'fulfilled' ? (runtimeNow.value as Runtime) : null
}

usePoll(sampleSystem, 3000)
usePoll(sampleConnections, 2000)
usePoll(loadState, 10000)

const names = computed(() => {
  const map = new Map<string, string>([
    ['final', '兜底分组'],
    ['direct', '直连'],
    ['block', '拒绝']
  ])
  for (const node of nodes.value) map.set(node.id, node.name)
  for (const group of groups.value) map.set(group.id, group.name)
  return map
})
const nameOf = (id: string | undefined) => (id ? (names.value.get(id) ?? id) : '—')

/** The node a group's traffic ends at (following groups that choose groups). */
function endNode(id: string | undefined): string | undefined {
  const seen = new Set<string>()
  let current = id
  while (current && runtime.value?.groups[current] && !seen.has(current)) {
    seen.add(current)
    current = runtime.value.groups[current].now
  }
  return current
}
const delayOf = (id: string | undefined) => (id ? runtime.value?.nodes[id] : undefined)

const nodeStats = computed(() => {
  const stats = { ok: 0, warn: 0, bad: 0, idle: 0 }
  for (const node of nodes.value) {
    const test = delayOf(node.id)
    stats[latency(test?.delay, test?.time)]++
  }
  return stats
})

const shownGroups = computed(() =>
  order.value.slice(0, 4).map((id) => {
    const now = runtime.value?.groups[id]?.now
    const test = delayOf(endNode(id))
    return { id, name: nameOf(id), now, kind: latency(test?.delay, test?.time), text: latencyText(test?.delay, test?.time) }
  })
)

const emptyGroups = computed(() => (status.value?.warnings.empty_groups ?? []).map(nameOf))
const enabledRules = computed(() => rules.value?.rules.filter((rule) => rule.enabled).length ?? 0)

const uptime = computed(() => {
  const started = system.value?.atomdns?.start_time_seconds
  return started ? duration(Date.now() / 1000 - started) : ''
})
const lastApply = computed(() => status.value?.last_apply ?? null)
const nftSync = computed(() => status.value?.nft.sync as { ok?: boolean; error?: string; sets?: { fakeip4?: string[]; iprule4?: string[] } } | null | undefined)

const applying = ref(false)
async function reapply() {
  applying.value = true
  try {
    await call(client.POST('/apply'))
    toast('ok', '已重新应用到 sing-box')
  } catch (error) {
    toast('bad', describe(error))
  } finally {
    applying.value = false
    refreshStatus().catch(() => {})
  }
}
</script>

<template>
  <div class="card">
    <div class="hd">
      <h2>服务状态</h2>
      <span class="sp"></span>
      <button class="btn sm" :disabled="applying" @click="reapply">重新应用</button>
    </div>
    <div class="grid g3">
      <div class="tile">
        <div class="k">atomdns</div>
        <div class="v">{{ status ? `运行中 · ${status.atomdns.version ?? ''}` : '—' }}</div>
        <div class="s" v-if="uptime">运行 {{ uptime }}</div>
      </div>
      <div class="tile">
        <div class="k">sing-box</div>
        <div class="v" :style="status && !status.singbox.running ? { color: 'var(--bad)' } : undefined">
          {{ !status ? '—' : status.singbox.running ? `运行中 · ${singboxVersion}` : '未运行' }}
        </div>
        <div class="s" v-if="status">{{ status.singbox.in_sync ? '配置已同步' : '配置未同步' }}</div>
      </div>
      <div class="tile">
        <div class="k">最近一次应用</div>
        <template v-if="lastApply">
          <div class="v" :style="{ color: lastApply.ok ? 'var(--ok)' : 'var(--bad)' }">{{ lastApply.ok ? '成功' : '失败' }}</div>
          <div class="s">
            {{ ago(lastApply.at) }} · {{ triggers[lastApply.trigger] ?? lastApply.trigger }}{{ lastApply.changed ? ' · 有变化' : '' }}
          </div>
          <div class="s" v-if="lastApply.error" style="color: var(--bad)">{{ lastApply.error }}</div>
        </template>
        <div class="v" v-else>—</div>
      </div>
    </div>
  </div>

  <div class="grid g2">
    <div class="card">
      <div class="hd">
        <h2>CPU 使用率</h2>
        <span class="sp"></span>
        <span class="big tnum">{{ system?.cpu && cpu.length ? `${cpu[cpu.length - 1].toFixed(1)}%` : '—' }}</span>
      </div>
      <svg class="spark" viewBox="0 0 300 70" preserveAspectRatio="none">
        <polygon :points="sparkArea(cpu, 100)" fill="var(--accent-soft)" />
        <polyline :points="sparkLine(cpu, 100)" fill="none" stroke="var(--accent)" stroke-width="1.6" vector-effect="non-scaling-stroke" />
      </svg>
      <div class="row t2">
        <span v-if="shares.atomdns != null">atomdns {{ shares.atomdns.toFixed(1) }}%</span>
        <span v-if="shares.singbox != null">sing-box {{ shares.singbox.toFixed(1) }}%</span>
        <span class="sp"></span>
        <span v-if="system?.cpu">{{ system.cpu.cores }} 核</span>
      </div>
    </div>
    <div class="card">
      <div class="hd">
        <h2>内存</h2>
        <span class="sp"></span>
        <span class="big tnum">{{ system?.memory && memory.length ? bytes(memory[memory.length - 1]) : '—' }}</span>
        <span class="muted" v-if="system?.memory">/ {{ bytes(system.memory.total_bytes) }}</span>
      </div>
      <svg class="spark" viewBox="0 0 300 70" preserveAspectRatio="none">
        <polygon :points="sparkArea(memory, system?.memory?.total_bytes ?? 1)" fill="var(--ok-soft)" />
        <polyline :points="sparkLine(memory, system?.memory?.total_bytes ?? 1)" fill="none" stroke="var(--ok)" stroke-width="1.6" vector-effect="non-scaling-stroke" />
      </svg>
      <div class="row t2">
        <span v-if="system?.atomdns">atomdns {{ bytes(system.atomdns.resident_bytes) }}</span>
        <span v-if="system?.singbox">sing-box {{ bytes(system.singbox.resident_bytes) }}</span>
        <span class="sp"></span>
        <span>整机</span>
      </div>
    </div>
  </div>

  <div class="grid g3">
    <div class="card">
      <div class="hd">
        <h2>节点</h2>
        <span class="sp"></span>
        <RouterLink class="btn sm ghost" to="/nodes">查看 →</RouterLink>
      </div>
      <div class="big">{{ nodes.length }}</div>
      <div v-if="!runtime" class="t2" style="margin-top: 6px">延迟不可用</div>
      <div v-else class="row" style="margin-top: 6px">
        <span class="pill ok">正常 {{ nodeStats.ok }}</span>
        <span class="pill warn">偏高 {{ nodeStats.warn }}</span>
        <span class="pill bad">失败 {{ nodeStats.bad }}</span>
        <span class="pill idle">未测 {{ nodeStats.idle }}</span>
      </div>
    </div>
    <div class="card">
      <div class="hd">
        <h2>节点组</h2>
        <span class="sp"></span>
        <RouterLink class="btn sm ghost" to="/groups">查看 →</RouterLink>
      </div>
      <div class="list">
        <div v-for="group in shownGroups" :key="group.id" class="row" style="padding: 4px 0">
          <span>{{ group.name }}</span>
          <span class="t2">→ {{ nameOf(group.now) }}</span>
          <span class="sp"></span>
          <span class="pill" :class="group.kind">{{ group.text }}</span>
        </div>
      </div>
      <div v-if="emptyGroups.length" class="err" style="margin-top: 8px">空组：{{ emptyGroups.join('、') }}</div>
    </div>
    <div class="card">
      <div class="hd">
        <h2>实时连接</h2>
        <span class="sp"></span>
        <RouterLink class="btn sm ghost" to="/connections">查看全部 →</RouterLink>
      </div>
      <div class="grid g3" style="gap: 8px">
        <div class="tile"><div class="k">连接</div><div class="v tnum">{{ traffic ? traffic.count : '—' }}</div></div>
        <div class="tile"><div class="k">↓ 下行</div><div class="v tnum">{{ traffic ? rate(traffic.down) : '—' }}</div></div>
        <div class="tile"><div class="k">↑ 上行</div><div class="v tnum">{{ traffic ? rate(traffic.up) : '—' }}</div></div>
      </div>
    </div>
  </div>

  <div class="grid g2">
    <div class="card">
      <div class="hd"><h2>配置摘要</h2></div>
      <div class="grid g2" style="gap: 8px">
        <div class="tile">
          <div class="k">规则</div>
          <div class="v">{{ rules ? `${rules.rules.length} 条 · 启用 ${enabledRules}` : '—' }}</div>
        </div>
        <div class="tile">
          <div class="k">FakeIP 网段</div>
          <div class="v mono">{{ settings?.fakeip_range ?? '—' }}</div>
        </div>
        <div class="tile">
          <div class="k">mixed 入站端口</div>
          <div class="v mono">{{ settings?.mixed_port ?? '—' }}</div>
        </div>
        <div class="tile">
          <div class="k">DNS 模式</div>
          <div class="v">{{ dns ? (dns.core_mode === 'safe' ? '安全模式' : '兼容模式') : '—' }}</div>
        </div>
      </div>
    </div>
    <div class="card">
      <div class="hd"><h2>绑定与 nft</h2></div>
      <div class="grid g2" style="gap: 8px">
        <div class="tile">
          <div class="k">绑定账本</div>
          <div class="v tnum">{{ status ? `${(status.bindings.size ?? 0).toLocaleString()} / ${(status.bindings.capacity ?? 0).toLocaleString()}` : '—' }}</div>
          <div class="s" v-if="status?.bindings.last">
            上次重算：{{ triggers[status.bindings.last.trigger ?? ''] ?? status.bindings.last.trigger }} · 改 {{ status.bindings.last.changed ?? 0 }} · 失败
            {{ status.bindings.last.failed ?? 0 }}
          </div>
        </div>
        <div class="tile">
          <div class="k">nft 集合</div>
          <template v-if="nftSync">
            <div class="v" :style="{ color: nftSync.ok ? 'var(--ok)' : 'var(--bad)' }">{{ nftSync.ok ? '已同步' : '同步失败' }}</div>
            <div class="s">fakeip4 {{ nftSync.sets?.fakeip4?.length ?? 0 }} 段 · iprule4 {{ nftSync.sets?.iprule4?.length ?? 0 }} 段</div>
            <div class="s" v-if="nftSync.error" style="color: var(--bad)">{{ nftSync.error }}</div>
          </template>
          <div class="v" v-else>—</div>
        </div>
      </div>
    </div>
  </div>
</template>
