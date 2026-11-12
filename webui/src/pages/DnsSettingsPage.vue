<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ApiError, call, client, describe, type Schemas } from '../api/client'
import AppModal from '../components/AppModal.vue'
import DnsTabs from '../components/DnsTabs.vue'
import { groupLabel, logTime } from '../composables/dnslog'
import { duration } from '../format'
import { usePoll } from '../composables/poll'
import { lines, loadUpstreams } from '../composables/rules'
import { toast } from '../composables/toast'

type Dns = Schemas['Dns']
type Toggle = 'block_qtypes' | 'block_aaaa' | 'prefer_v4' | 'block_empty' | 'full_cache' | 'lazy_cache'
type LearnKey = 'remember_direct' | 'remember_proxy' | 'no_v4' | 'no_v6'
const RESOLVE: [Toggle, string][] = [
  ['prefer_v4', 'IPv4 优先'],
  ['block_aaaa', 'IPv6 屏蔽'],
  ['block_qtypes', '类型屏蔽（SOA/PTR/HTTPS）'],
  ['block_empty', '空结果屏蔽']
]
const CACHE: [Toggle, string][] = [
  ['full_cache', '未命中规则的缓存'],
  ['lazy_cache', '上游应答缓存']
]
const LEARN: Record<LearnKey, string> = { remember_direct: '直连', remember_proxy: '代理', no_v4: '无 V4', no_v6: '无 V6' }

const dns = ref<Dns | null>(null)
const form = reactive({
  core_mode: 'compat' as 'compat' | 'safe',
  ecs: '',
  block_qtypes: false,
  block_aaaa: false,
  prefer_v4: false,
  block_empty: false,
  full_cache: false,
  lazy_cache: false,
  learning: { enabled: false, remember_direct: false, remember_proxy: false, no_v4: false, no_v6: false }
})
const settings = ref<Schemas['Settings'] | null>(null)
const ttl = reactive({ direct: '', fakeip: '' })
const caches = ref<Schemas['Cache'][]>([])
const learning = ref<Schemas['LearningState'] | null>(null)
const requery = ref<Schemas['Requery'] | null>(null)
const refresh = reactive({ enabled: false, interval: '' })
const audit = reactive({ capturing: false, capacity: 0, wanted: '' })
const rewrite = ref('')
const savedRewrite = ref('')
// A save replaces every rewrite rule: the editor opens only once the rules were read.
const rewriteRead = ref(false)
const rewriteError = ref('')
const errors = reactive({ load: '', resolve: '', cache: '', learning: '', refresh: '', ttl: '', audit: '', rewrite: '' })
const busy = ref('')

async function loadRewrite() {
  rewriteError.value = ''
  try {
    const answer = await call(client.GET('/rewrite'))
    savedRewrite.value = answer.entries.join('\n')
    rewrite.value = savedRewrite.value
    rewriteRead.value = true
  } catch (failure) {
    rewriteError.value = `读取失败：${describe(failure)}`
  }
}

type Part = 'resolve' | 'cache' | 'learning'
const PARTS: Record<Part, (keyof typeof form)[]> = {
  resolve: ['core_mode', 'ecs', 'prefer_v4', 'block_aaaa', 'block_qtypes', 'block_empty'],
  cache: ['full_cache', 'lazy_cache'],
  learning: ['learning']
}

/**
 * The stored values. The fields of `parts` replace the form; a card not in `parts` keeps its
 * fields only while they hold unsaved edits, otherwise it follows the new values too.
 */
function fillDns(value: Dns, parts: Part[] = ['resolve', 'cache', 'learning']) {
  const follow = (Object.keys(PARTS) as Part[]).filter((part) => parts.includes(part) || !changed(part))
  dns.value = value
  const keys = follow.flatMap((part) => PARTS[part])
  const next = {
    core_mode: value.core_mode,
    ecs: value.ecs,
    block_qtypes: value.block_qtypes,
    block_aaaa: value.block_aaaa,
    prefer_v4: value.prefer_v4,
    block_empty: value.block_empty,
    full_cache: value.full_cache,
    lazy_cache: value.lazy_cache,
    learning: {
      enabled: !!value.learning?.enabled,
      remember_direct: !!value.learning?.remember_direct,
      remember_proxy: !!value.learning?.remember_proxy,
      no_v4: !!value.learning?.no_v4,
      no_v6: !!value.learning?.no_v6
    }
  }
  for (const key of keys) Object.assign(form, { [key]: key === 'learning' ? { ...next.learning } : next[key] })
}
function fillSettings(value: Schemas['Settings']) {
  settings.value = value
  ttl.direct = String(value.direct_ttl_max)
  ttl.fakeip = String(value.fakeip_ttl_max)
}
// Reads and writes of the re-query state take a number in order (a read when it is sent, a
// write when it answers); a read answering after a later one was applied is dropped.
let requeryTicket = 0
let requeryApplied = 0
function fillRequery(value: Schemas['Requery']) {
  requeryApplied = ++requeryTicket
  requery.value = value
  refresh.enabled = value.enabled
  refresh.interval = value.interval_minutes > 0 ? String(value.interval_minutes) : ''
}
const auditRead = ref(false)
const loadCaches = async () => (caches.value = (await call(client.GET('/caches'))).caches)
const loadLearning = async () => (learning.value = await call(client.GET('/learning')))
/** The recording switch and the capacity; the card can be used once both were read. */
async function loadAudit() {
  const [status, capacity] = await Promise.all([call(client.GET('/audit/status')), call(client.GET('/audit/capacity'))])
  audit.capturing = status.capturing
  audit.capacity = capacity.capacity
  audit.wanted = String(capacity.capacity)
  auditRead.value = true
}

onMounted(async () => {
  const results = await Promise.allSettled([
    call(client.GET('/dns')).then((value) => fillDns(value)),
    call(client.GET('/settings')).then(fillSettings),
    call(client.GET('/requery')).then(fillRequery),
    loadCaches(),
    loadLearning(),
    loadAudit().catch((failure) => {
      errors.audit = `读取失败：${describe(failure)}`
      throw failure
    }),
    loadUpstreams(),
    loadRewrite()
  ])
  const failed = results.find((result) => result.status === 'rejected')
  errors.load = failed ? describe((failed as PromiseRejectedResult).reason) : ''
})

// Only what changed is sent (the last write wins: `dns` carries no version).
function patchOf(part: Part): Schemas['DnsPatch'] {
  const current = dns.value
  if (!current) return {}
  const patch: Record<string, unknown> = {}
  for (const key of PARTS[part]) {
    if (key === 'learning') {
      const changed = Object.entries(form.learning).filter(([name, value]) => value !== !!current.learning?.[name as keyof Schemas['Learning']])
      if (changed.length) patch.learning = Object.fromEntries(changed)
    } else if (key === 'ecs') {
      if (form.ecs.trim() !== current.ecs) patch.ecs = form.ecs.trim()
    } else if (form[key] !== current[key]) {
      patch[key] = form[key]
    }
  }
  return patch as Schemas['DnsPatch']
}
const changed = (part: Part) => Object.keys(patchOf(part)).length > 0

async function saveDns(part: Part) {
  busy.value = part
  errors[part] = ''
  try {
    fillDns(await call(client.PUT('/dns', { body: patchOf(part) })), [part])
    toast('ok', '已保存')
    // A cache switch turned off emptied its caches, a learning switch its list.
    const [cachesNow, learningNow] = await Promise.allSettled([loadCaches(), loadLearning()])
    if (cachesNow.status === 'rejected') errors.cache = `缓存状态读取失败：${describe(cachesNow.reason)}`
    if (learningNow.status === 'rejected') errors.learning = `学习状态读取失败：${describe(learningNow.reason)}`
  } catch (failure) {
    errors[part] = describe(failure)
  } finally {
    busy.value = ''
  }
}

// ---- caches -------------------------------------------------------------------

const cacheRows = computed(() =>
  caches.value.map((item) => ({
    ...item,
    name: item.tag.startsWith('cache_atom_') && item.group ? `${item.label}·${groupLabel(item.group)}` : item.label || item.tag,
    hitRate: item.queries ? `${((item.hits / item.queries) * 100).toFixed(1)}%` : '—',
    off: (item.switch === 'full_cache' && !dns.value?.full_cache) || (item.switch === 'lazy_cache' && !dns.value?.lazy_cache)
  }))
)
/** Whole days or hours as such (`7 天`), anything else as a duration. */
function span(seconds: number): string {
  if (seconds > 0 && seconds % 86400 === 0) return `${seconds / 86400} 天`
  if (seconds > 0 && seconds % 3600 === 0) return `${seconds / 3600} 小时`
  return duration(seconds)
}
const keep = (seconds: number) => (seconds > 0 ? span(seconds) : '不保留')

// ---- learning and requery ------------------------------------------------------

const learnRows = computed(() => (learning.value?.categories ?? []).map((item) => ({ ...item, name: LEARN[item.key as LearnKey] ?? item.label })))

const refreshChanged = computed(() => !!requery.value && (refresh.enabled !== requery.value.enabled || refresh.interval.trim() !== (requery.value.interval_minutes > 0 ? String(requery.value.interval_minutes) : '')))
async function saveRefresh() {
  const minutes = Number(refresh.interval.trim())
  if (!Number.isInteger(minutes) || minutes < 1 || minutes > 525600) {
    errors.refresh = '间隔应为 1–525600 的整数（分钟）'
    return
  }
  busy.value = 'refresh'
  errors.refresh = ''
  try {
    fillRequery(await call(client.PUT('/requery', { body: { enabled: refresh.enabled, interval_minutes: minutes } })))
    toast('ok', '已保存')
  } catch (failure) {
    errors.refresh = describe(failure)
  } finally {
    busy.value = ''
  }
}
async function runRefresh() {
  busy.value = 'refresh'
  errors.refresh = ''
  try {
    const value = await call(client.POST('/requery/trigger'))
    // Only the run state: the schedule may hold unsaved edits.
    requeryApplied = ++requeryTicket
    if (requery.value) requery.value = { ...requery.value, status: value.status }
    else fillRequery(value)
    toast('ok', '已开始刷新')
  } catch (failure) {
    errors.refresh = describe(failure)
  } finally {
    busy.value = ''
  }
}
// The run state is read again every few seconds (a scheduled run, a run's progress); only the
// state is replaced, the schedule may hold unsaved edits.
const statusError = ref('')
usePoll(async () => {
  if (!requery.value) return
  const ticket = ++requeryTicket
  try {
    const value = await call(client.GET('/requery'))
    if (ticket < requeryApplied) return
    requeryApplied = ticket
    if (requery.value) requery.value = { ...requery.value, status: value.status }
    statusError.value = ''
  } catch (failure) {
    statusError.value = `读取刷新状态失败：${describe(failure)}`
  }
}, 5000)
const STATES: Record<string, string> = { idle: '空闲', running: '运行中', failed: '失败', cancelled: '已取消', canceled: '已取消' }
const lastRun = computed(() => {
  const status = requery.value?.status
  if (!status) return '—'
  const at = status.last_run_end_time || status.last_run_start_time
  const state = STATES[status.task_state ?? ''] ?? status.task_state ?? ''
  if (status.task_state === 'running') return `${state} ${status.progress?.processed ?? 0} / ${status.progress?.total ?? 0}`
  return at ? `${logTime(at, true)} · ${status.last_run_domain_count ?? 0} 个域名${state && status.task_state !== 'idle' ? ` · ${state}` : ''}` : '—'
})

// ---- TTL caps ------------------------------------------------------------------

const ttlChanged = computed(() => !!settings.value && (ttl.direct.trim() !== String(settings.value.direct_ttl_max) || ttl.fakeip.trim() !== String(settings.value.fakeip_ttl_max)))
async function saveTtl() {
  const current = settings.value
  if (!current) return
  const direct = Number(ttl.direct.trim())
  const fakeip = Number(ttl.fakeip.trim())
  if (![direct, fakeip].every((value) => Number.isInteger(value) && value >= 1 && value <= 86400)) {
    errors.ttl = 'TTL 上限应为 1–86400 的整数'
    return
  }
  busy.value = 'ttl'
  errors.ttl = ''
  try {
    fillSettings(await call(client.PUT('/settings', { body: { direct_ttl_max: direct, fakeip_ttl_max: fakeip, version: current.version } })))
    toast('ok', '已保存')
  } catch (failure) {
    if (failure instanceof ApiError && failure.status === 409 && failure.body?.version !== undefined) {
      try {
        fillSettings(await call(client.GET('/settings')))
        errors.ttl = '设置已在别处修改，已载入最新内容（409）'
      } catch (reload) {
        errors.ttl = `设置已在别处修改（409），重新读取失败：${describe(reload)}`
      }
    } else {
      errors.ttl = describe(failure)
    }
  } finally {
    busy.value = ''
  }
}

// ---- query log -----------------------------------------------------------------

async function toggleAudit() {
  busy.value = 'audit'
  errors.audit = ''
  try {
    const wanted = !audit.capturing
    await call(wanted ? client.POST('/audit/start') : client.POST('/audit/stop'))
    // Done: the switch shows it even if reading it back fails.
    audit.capturing = wanted
    try {
      audit.capturing = (await call(client.GET('/audit/status'))).capturing
    } catch (failure) {
      errors.audit = `已${wanted ? '开始' : '停止'}记录，读取状态失败：${describe(failure)}`
    }
  } catch (failure) {
    errors.audit = describe(failure)
  } finally {
    busy.value = ''
  }
}

// ---- clearing (confirmed first) ------------------------------------------------

const confirming = ref<{ title: string; text: string; run: () => Promise<unknown> } | null>(null)
function clearCache(item: { tag: string; name: string }) {
  confirming.value = {
    title: `清空「${item.name}」`,
    text: '缓存的应答全部丢弃，之后的查询重新问上游。',
    run: async () => (caches.value = (await call(client.POST('/caches/{tag}/flush', { params: { path: { tag: item.tag } } }))).caches)
  }
}
function clearLearned(item: { key: string; name: string }) {
  confirming.value = {
    title: `清空学到的「${item.name}」`,
    text: '这一类学到的域名全部删除。',
    run: async () =>
      (learning.value = await call(client.POST('/learning/{key}/flush', { params: { path: { key: item.key as LearnKey } } })))
  }
}
function clearLogs() {
  confirming.value = {
    title: '清空查询日志',
    text: '记录的查询全部删除，概览的统计从零开始。',
    run: () => call(client.POST('/audit/clear'))
  }
}
function changeCapacity() {
  const wanted = Number(audit.wanted.trim())
  if (!Number.isInteger(wanted) || wanted < 0 || wanted > 400000) {
    errors.audit = '容量应为 0–400000 的整数'
    return
  }
  errors.audit = ''
  confirming.value = {
    title: '修改日志容量',
    text: `容量改为 ${wanted.toLocaleString()} 条，已记录的查询会被清空。`,
    run: async () => {
      await call(client.POST('/audit/capacity', { body: { capacity: wanted } }))
      // Done (the records were dropped): reading back failing does not make it a failure to retry.
      audit.capacity = wanted
      audit.wanted = String(wanted)
      loadAudit().catch((failure) => (errors.audit = `容量已修改，读取失败：${describe(failure)}`))
    }
  }
}
async function confirm() {
  const job = confirming.value
  if (!job) return
  busy.value = 'confirm'
  try {
    await job.run()
    toast('ok', '已完成')
    confirming.value = null
  } catch (failure) {
    toast('bad', describe(failure))
  } finally {
    busy.value = ''
  }
}

async function saveRewrite() {
  busy.value = 'rewrite'
  errors.rewrite = ''
  try {
    const answer = await call(client.PUT('/rewrite', { body: { entries: lines(rewrite.value) } }))
    savedRewrite.value = answer.entries.join('\n')
    rewrite.value = savedRewrite.value
    toast('ok', '已保存')
  } catch (failure) {
    errors.rewrite = describe(failure)
  } finally {
    busy.value = ''
  }
}
</script>

<template>
  <DnsTabs />
  <div v-if="errors.load" class="err">{{ errors.load }}</div>
  <!-- A save answers with the stored values, which replace the form: nothing is edited meanwhile. -->
  <fieldset class="plain grid" :disabled="!!busy">
    <div class="split3">
      <div class="grid" style="gap: 16px">
        <div v-if="dns" class="card grid" style="gap: 14px">
          <div class="hd" style="margin: 0">
            <h2>解析</h2>
            <span class="sp"></span>
            <button class="btn sm pri" type="button" :disabled="!!busy || !changed('resolve')" @click="saveDns('resolve')">保存</button>
          </div>
          <div class="field">
            <span class="label">核心模式</span>
            <div class="seg" style="align-self: flex-start">
              <button type="button" :class="{ on: form.core_mode === 'compat' }" @click="form.core_mode = 'compat'">兼容模式</button>
              <button type="button" :class="{ on: form.core_mode === 'safe' }" @click="form.core_mode = 'safe'">安全模式</button>
            </div>
          </div>
          <div class="field">
            <label for="ecs">ECS 地址</label>
            <input id="ecs" v-model="form.ecs" class="inp mono" placeholder="留空用默认" autocomplete="off" />
          </div>
          <div v-for="item in RESOLVE" :key="item[0]" class="row">
            <div style="flex: 1">{{ item[1] }}</div>
            <button class="sw" type="button" :class="{ on: form[item[0]] }" :aria-pressed="form[item[0]]" :aria-label="item[1]" @click="form[item[0]] = !form[item[0]]"></button>
          </div>
          <div v-if="errors.resolve" class="err">{{ errors.resolve }}</div>
        </div>

        <div v-if="dns" class="card grid" style="gap: 12px">
          <div class="hd" style="margin: 0">
            <h2>缓存</h2>
            <span class="sp"></span>
            <button class="btn sm pri" type="button" :disabled="!!busy || !changed('cache')" @click="saveDns('cache')">保存</button>
          </div>
          <div v-for="item in CACHE" :key="item[0]" class="row">
            <div style="flex: 1">{{ item[1] }}</div>
            <button class="sw" type="button" :class="{ on: form[item[0]] }" :aria-pressed="form[item[0]]" :aria-label="item[1]" @click="form[item[0]] = !form[item[0]]"></button>
          </div>
          <div v-if="errors.cache" class="err">{{ errors.cache }}</div>
          <div class="tblwrap">
            <table>
              <thead>
                <tr><th>缓存</th><th class="num">条目</th><th class="num">命中率</th><th class="num">容量上限</th><th>过期保留</th><th>写盘间隔</th><th></th></tr>
              </thead>
              <tbody>
                <tr v-for="item in cacheRows" :key="item.tag" :class="{ off: item.off }">
                  <td>{{ item.name }}</td>
                  <td class="num tnum">{{ item.entries.toLocaleString() }}</td>
                  <td class="num tnum">{{ item.hitRate }}</td>
                  <td class="num tnum">{{ item.capacity.toLocaleString() }}</td>
                  <td>{{ keep(item.lazy_cache_ttl) }}</td>
                  <td>{{ span(item.dump_interval) }}</td>
                  <td><button class="btn sm danger" type="button" @click="clearCache(item)">清空</button></td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <div v-if="dns" class="card grid" style="gap: 12px">
          <div class="hd" style="margin: 0">
            <h2>域名学习</h2>
            <span class="sp"></span>
            <button class="btn sm pri" type="button" :disabled="!!busy || !changed('learning')" @click="saveDns('learning')">保存</button>
          </div>
          <div class="row">
            <div style="flex: 1">学习</div>
            <button class="sw" type="button" :class="{ on: form.learning.enabled }" :aria-pressed="form.learning.enabled" aria-label="域名学习" @click="form.learning.enabled = !form.learning.enabled"></button>
          </div>
          <div class="tblwrap">
            <table>
              <thead>
                <tr><th>类别</th><th>开关</th><th class="num">条数</th><th class="num">上限</th><th>有效期</th><th></th></tr>
              </thead>
              <tbody>
                <tr v-for="item in learnRows" :key="item.key" :class="{ off: !form.learning.enabled }">
                  <td>{{ item.name }}</td>
                  <td>
                    <button
                      class="sw"
                      type="button"
                      :class="{ on: form.learning[item.key as LearnKey] }"
                      :aria-pressed="form.learning[item.key as LearnKey]"
                      :aria-label="item.name"
                      @click="form.learning[item.key as LearnKey] = !form.learning[item.key as LearnKey]"
                    ></button>
                  </td>
                  <td class="num tnum">{{ item.entries.toLocaleString() }}</td>
                  <td class="num tnum">{{ item.max_entries.toLocaleString() }}</td>
                  <td>{{ span(item.ttl_seconds) }}</td>
                  <td><button class="btn sm danger" type="button" @click="clearLearned(item)">清空</button></td>
                </tr>
              </tbody>
            </table>
          </div>
          <div v-if="errors.learning" class="err">{{ errors.learning }}</div>
          <div v-if="requery" class="grid" style="gap: 10px; border-top: 1px solid var(--line); padding-top: 12px">
            <div class="row">
              <div style="flex: 1">定期刷新</div>
              <button class="sw" type="button" :class="{ on: refresh.enabled }" :aria-pressed="refresh.enabled" aria-label="定期刷新" @click="refresh.enabled = !refresh.enabled"></button>
            </div>
            <div class="row">
              <label for="interval" class="t2">间隔（分钟）</label>
              <input id="interval" v-model="refresh.interval" class="inp sm mono" style="width: 110px" inputmode="numeric" autocomplete="off" />
              <span class="sp"></span>
              <button class="btn sm" type="button" :disabled="!!busy" @click="runRefresh">立即刷新</button>
              <button class="btn sm pri" type="button" :disabled="!!busy || !refreshChanged" @click="saveRefresh">保存</button>
            </div>
            <div class="row t2"><span>上次运行</span><span class="tnum">{{ lastRun }}</span></div>
            <div v-if="errors.refresh" class="err">{{ errors.refresh }}</div>
            <div v-if="statusError" class="err">{{ statusError }}</div>
          </div>
        </div>
      </div>

      <div class="grid" style="gap: 16px">
        <div v-if="settings" class="card grid" style="gap: 10px">
          <div class="hd" style="margin: 0">
            <h2>TTL 上限</h2>
            <span class="sp"></span>
            <button class="btn sm pri" type="button" :disabled="!!busy || !ttlChanged" @click="saveTtl">保存</button>
          </div>
          <div class="grid g2" style="gap: 10px">
            <div class="field">
              <label for="dttl">直连应答（秒）</label>
              <input id="dttl" v-model="ttl.direct" class="inp mono" inputmode="numeric" autocomplete="off" />
            </div>
            <div class="field">
              <label for="fttl">FakeIP 应答（秒）</label>
              <input id="fttl" v-model="ttl.fakeip" class="inp mono" inputmode="numeric" autocomplete="off" />
            </div>
          </div>
          <div v-if="errors.ttl" class="err">{{ errors.ttl }}</div>
        </div>
        <div class="card">
          <fieldset class="plain grid" style="gap: 10px" :disabled="!auditRead">
            <div class="hd" style="margin: 0"><h2>查询日志</h2></div>
            <div class="row">
              <div style="flex: 1">记录</div>
              <button class="sw" type="button" :class="{ on: audit.capturing }" :aria-pressed="audit.capturing" aria-label="记录查询日志" @click="toggleAudit"></button>
            </div>
            <div class="row">
              <label for="capacity" class="t2">容量（条）</label>
              <input id="capacity" v-model="audit.wanted" class="inp sm mono" style="width: 120px" inputmode="numeric" autocomplete="off" />
              <span class="sp"></span>
              <button class="btn sm pri" type="button" :disabled="!!busy || audit.wanted.trim() === String(audit.capacity)" @click="changeCapacity">保存</button>
            </div>
            <div class="row">
              <span class="sp"></span>
              <button class="btn sm danger" type="button" @click="clearLogs">清空日志</button>
            </div>
            <div v-if="errors.audit" class="err">{{ errors.audit }}</div>
          </fieldset>
        </div>
      </div>
    </div>

    <div class="card grid" style="gap: 10px">
      <div class="hd" style="margin: 0">
        <h2>重写 / hosts</h2>
        <span v-if="rewriteRead" class="tag">{{ lines(rewrite).length }} 行</span>
        <span class="sp"></span>
        <button v-if="rewriteRead" class="btn sm pri" type="button" :disabled="!!busy || rewrite === savedRewrite" @click="saveRewrite">保存</button>
      </div>
      <textarea v-if="rewriteRead" v-model="rewrite" class="inp" aria-label="重写规则" placeholder="full:router.lan 192.168.1.1&#10;domain:corp.example.com 10.8.0.10"></textarea>
      <div v-else-if="rewriteError" class="row">
        <div class="err" style="flex: 1">{{ rewriteError }}</div>
        <button class="btn" type="button" @click="loadRewrite">重试</button>
      </div>
      <div v-if="errors.rewrite" class="err">{{ errors.rewrite }}</div>
    </div>
  </fieldset>

  <AppModal v-if="confirming" :title="confirming.title" @close="confirming = null">
    <div>{{ confirming.text }}</div>
    <template #footer>
      <button class="btn" type="button" @click="confirming = null">取消</button>
      <button class="btn red" type="button" :disabled="busy === 'confirm'" @click="confirm">确定</button>
    </template>
  </AppModal>
</template>
