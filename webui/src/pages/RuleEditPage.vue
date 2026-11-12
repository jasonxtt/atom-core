<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ApiError, call, client, describe, type Schemas } from '../api/client'
import SourcePicker, { type Source } from '../components/SourcePicker.vue'
import { loadProxy } from '../composables/proxy'
import {
  actionLabel,
  dnsLabel,
  isCatalogId,
  lines,
  loadRules,
  loadRulesets,
  loadUpstreams,
  namesText,
  parseNames,
  proxyTargets,
  rules,
  rulesets,
  rulesVersion,
  setName,
  summary,
  upstreamGroups,
  type Match,
  type Rule
} from '../composables/rules'
import { refreshStatus } from '../composables/status'
import { toast } from '../composables/toast'
import { parseHeadlessRule, parsePorts, portsText, TRANSPORT_WITH_NAMES } from '../singboxRule'

const route = useRoute()
const router = useRouter()
// `/rules/new` has no `id` parameter.
const id = computed(() => (typeof route.params.id === 'string' ? route.params.id : ''))

type Part = 'domain' | 'ip' | 'all'
type Kind = 'source' | 'set' | 'domain' | 'ip' | 'client' | 'port' | 'network'
interface Cond {
  key: number
  t: Kind
  /** source / set: the ruleset reference; `__new` while a subscription is being made. */
  ref: string
  label: string
  provider: string
  /** What the source holds (null: unknown). */
  names: boolean | null
  ips: boolean | null
  part: Part
  text: string
  /** network: the networks chosen. */
  nets: string[]
  invert: boolean
  sub: { name: string; url: string; format: string; category: string }
}

let nextKey = 0
const blank = (t: Kind): Cond => ({
  key: nextKey++,
  t,
  ref: '',
  label: '',
  provider: '',
  names: null,
  ips: null,
  part: 'domain',
  text: '',
  nets: [],
  invert: false,
  sub: { name: '', url: '', format: 'auto', category: '' }
})

const form = reactive({
  remark: '',
  enabled: true,
  conds: [] as Cond[],
  action: 'direct' as 'proxy' | 'direct' | 'block',
  group: 'final',
  dns: '',
  cache: true
})
const loaded = ref(false)
const error = ref('')
const saving = ref(false)
const formVersion = ref(0)
const conflict = ref<Rule | null>(null)

const FORMATS = ['auto', 'text', 'yaml', 'json', 'srs', 'mrs', 'dat']

/** A ruleset reference as a condition: a custom one is "自定义规则集", the rest are builtin sets. */
function refCond(refId: string, part: Part): Cond {
  const custom = rulesets.value.find((set) => set.id === refId && set.type !== 'catalog')
  const cond = blank(custom ? 'set' : 'source')
  cond.ref = refId
  cond.part = part
  cond.label = setName(refId)
  cond.provider = isCatalogId(refId) ? (refId.startsWith('meta:') ? 'MetaCubeX' : 'blackmatrix7') : '默认'
  if (!isCatalogId(refId) && !custom) {
    cond.names = true
    cond.ips = false
  }
  return cond
}

function fill(rule: Rule | undefined) {
  formVersion.value = rulesVersion.value
  conflict.value = null
  if (!rule) return
  const match = rule.match
  const conds: Cond[] = []
  const sets = match.ruleset ?? []
  const ipSets = match.ip_ruleset ?? []
  for (const refId of sets) conds.push(refCond(refId, ipSets.includes(refId) ? 'all' : 'domain'))
  for (const refId of ipSets.filter((item) => !sets.includes(item))) conds.push(refCond(refId, 'ip'))
  const names = namesText(match)
  if (names) conds.push({ ...blank('domain'), text: names })
  if (match.ip_cidr?.length) conds.push({ ...blank('ip'), text: match.ip_cidr.join('\n') })
  if (match.port?.length || match.port_range?.length) conds.push({ ...blank('port'), text: portsText(match.port, match.port_range) })
  if (match.network?.length) conds.push({ ...blank('network'), nets: [...match.network] })
  if (match.client?.length) conds.push({ ...blank('client'), text: match.client.join('\n'), invert: !!match.client_invert })
  Object.assign(form, {
    remark: rule.remark,
    enabled: rule.enabled,
    conds,
    action: rule.action.type,
    group: rule.action.type === 'proxy' ? rule.action.group_id : 'final',
    dns: rule.dns ?? '',
    cache: rule.cache !== false
  })
}

// The form opens only when everything it shows and saves was read (the rule table, the
// rulesets, the upstream groups, the node groups) and the rule edited exists; else the error
// and a retry.
async function load() {
  loaded.value = false
  error.value = ''
  try {
    await Promise.all([loadRules(), loadRulesets(), loadUpstreams(), loadProxy()])
  } catch (failure) {
    error.value = `读取失败：${describe(failure)}`
    return
  }
  const rule = rules.value.find((item) => item.id === id.value)
  if (id.value && !rule) {
    error.value = '规则不存在'
    return
  }
  fill(rule)
  loaded.value = true
}
onMounted(load)

// ---- conditions -----------------------------------------------------------------
const hasClient = computed(() => form.conds.some((cond) => cond.t === 'client'))
const isTransport = (cond: Cond) => cond.t === 'port' || cond.t === 'network'
const hasTransport = computed(() => form.conds.some(isTransport))
/** A condition matched on names (DNS). */
const takesNames = (cond: Cond) => cond.t === 'domain' || ((cond.t === 'source' || cond.t === 'set') && cond.part !== 'ip')

// The blocks shown by how they combine: names, then the IP part (either one matches), then
// ports and networks, then clients (each and-ed with what is before it).
const rank = (cond: Cond) => (cond.t === 'client' ? 4 : cond.t === 'network' ? 3 : cond.t === 'port' ? 2 : takesNames(cond) ? 0 : 1)
const ordered = computed(() =>
  form.conds
    .map((cond, index) => ({ cond, index }))
    .sort((a, b) => rank(a.cond) - rank(b.cond) || a.index - b.index)
    .map((item, position, all) => {
      const before = position ? rank(all[position - 1].cond) : -1
      const own = rank(item.cond)
      return { ...item, joint: before < 0 ? '' : before === own || own <= 1 ? '或' : '且' }
    })
)
const customSets = computed(() => rulesets.value.filter((set) => set.type !== 'catalog'))

function add(t: Kind) {
  form.conds.push(blank(t))
}

/** Keeps a source's part one it may take (names first). */
function fitPart(cond: Cond) {
  if (partOk(cond, cond.part)) return
  cond.part = (['domain', 'ip', 'all'] as const).find((part) => partOk(cond, part)) ?? 'domain'
}

function pickSource(cond: Cond, source: Source) {
  cond.ref = source.id
  cond.label = source.name
  cond.provider = source.provider
  cond.names = source.names
  cond.ips = source.ips
  cond.part = 'domain'
  fitPart(cond)
}

function pickSet(cond: Cond, value: string) {
  cond.ref = value
  const set = rulesets.value.find((item) => item.id === value)
  // A set not downloaded yet may hold either.
  cond.names = set && set.updated_at ? set.rule_count > 0 : null
  cond.ips = set && set.updated_at ? (set.ip_count ?? 0) > 0 : null
  cond.label = set?.name ?? value
  fitPart(cond)
}

/** Whether a source condition may take `part` (a rule with a client takes names only, one with
 * ports or networks IP prefixes only). */
function partOk(cond: Cond, part: Part) {
  if (part !== 'domain' && hasClient.value) return false
  if (part !== 'ip' && hasTransport.value) return false
  if (part === 'domain') return cond.names !== false
  if (part === 'ip') return cond.ips !== false
  return cond.names !== false && cond.ips !== false
}

function setKind(cond: Cond, t: Kind) {
  cond.t = t
}

/** Whether `cond` may become kind `t`, beside the other conditions. */
function kindOk(cond: Cond, t: Kind) {
  const others = form.conds.filter((item) => item !== cond)
  if (t === 'ip') return !others.some((item) => item.t === 'client')
  if (t === 'client') return !others.some((item) => item.t === 'client' || item.t === 'ip' || item.part !== 'domain' || isTransport(item))
  if (t === 'domain') return !others.some(isTransport)
  return !others.some((item) => takesNames(item) || item.t === 'client')
}

function toggleNet(cond: Cond, network: string) {
  cond.nets = cond.nets.includes(network) ? cond.nets.filter((item) => item !== network) : [...cond.nets, network].sort()
}

// ---- a pasted sing-box headless rule -------------------------------------------------
const pasting = ref(false)
const pasted = ref('')
const pasteError = ref('')
function importRule() {
  const result = parseHeadlessRule(pasted.value)
  if ('error' in result) {
    pasteError.value = result.error
    return
  }
  const fields = result.fields
  const names = namesText({ domain: fields.domain, suffix: fields.suffix, keyword: fields.keyword, regex: fields.regex })
  if (names) form.conds.push({ ...blank('domain'), text: names })
  if (fields.ip_cidr.length) form.conds.push({ ...blank('ip'), text: fields.ip_cidr.join('\n') })
  if (fields.port.length || fields.port_range.length) form.conds.push({ ...blank('port'), text: portsText(fields.port, fields.port_range) })
  if (fields.network.length) form.conds.push({ ...blank('network'), nets: [...fields.network].sort() })
  if (fields.client.length) form.conds.push({ ...blank('client'), text: fields.client.join('\n') })
  pasted.value = ''
  pasteError.value = ''
  pasting.value = false
}

const creating = ref(false)
async function createSub(cond: Cond) {
  const { name, url, format, category } = cond.sub
  creating.value = true
  error.value = ''
  try {
    const body = { type: 'remote' as const, name: name.trim() || url.trim(), url: url.trim(), format, ...(category.trim() ? { category: category.trim() } : {}) }
    let set: Schemas['Ruleset']
    try {
      set = await call(client.POST('/rulesets', { body }))
    } catch (failure) {
      // Created, but its first download failed: it is selected, the reason is shown.
      const created = failure instanceof ApiError && failure.status === 502 ? (failure.body as unknown as Schemas['Ruleset'] | undefined) : undefined
      if (!created?.id) throw failure
      set = created
      toast('warn', `已创建「${set.name}」，但第一次下载失败：${failure instanceof ApiError ? failure.message : ''}`)
    }
    await loadRulesets()
    pickSet(cond, set.id)
    cond.label = set.name
  } catch (failure) {
    error.value = describe(failure)
  } finally {
    creating.value = false
  }
}

const nameStats = (text: string) => {
  const parsed = parseNames(text)
  return parsed.bad.length ? `无法识别：${parsed.bad.slice(0, 3).join('、')}` : `${parsed.count} 条`
}

// ---- the rule ---------------------------------------------------------------------
/** The rule the form describes, or the reason it is not one yet. */
const built = computed((): { match: Match; problem: string } => {
  const match: Match = {}
  const push = (field: keyof Match, values: string[]) => {
    if (!values.length) return
    const list = ((match[field] as string[] | undefined) ?? []) as string[]
    for (const value of values) if (!list.includes(value)) list.push(value)
    ;(match as Record<string, unknown>)[field] = list
  }
  let problem = ''
  for (const cond of form.conds) {
    if (cond.t === 'source' || cond.t === 'set') {
      if (!cond.ref || cond.ref === '__new') {
        problem ||= cond.t === 'source' ? '有内置规则集还没选' : '有自定义规则集还没选'
        continue
      }
      if (!partOk(cond, cond.part)) {
        problem ||= hasClient.value
          ? `「${cond.label}」只能取域名部分（有客户端条件）`
          : hasTransport.value
            ? `「${cond.label}」只能取 IP 部分（有端口或网络条件）`
            : `「${cond.label}」没有${cond.part === 'ip' ? ' IP' : '域名'}部分`
      }
      if (cond.part !== 'ip') push('ruleset', [cond.ref])
      if (cond.part !== 'domain') push('ip_ruleset', [cond.ref])
    } else if (cond.t === 'domain') {
      const parsed = parseNames(cond.text)
      if (parsed.bad.length) problem ||= `域名无法识别：${parsed.bad[0]}`
      if (!parsed.count) problem ||= '域名条件是空的'
      for (const [field, values] of Object.entries(parsed.fields)) push(field as keyof Match, values)
    } else if (cond.t === 'ip') {
      const values = lines(cond.text)
      if (!values.length) problem ||= '目标 IP 网段是空的'
      push('ip_cidr', values)
    } else if (cond.t === 'port') {
      const parsed = parsePorts(cond.text)
      if (parsed.bad.length) problem ||= `端口无法识别：${parsed.bad[0]}`
      if (!parsed.port.length && !parsed.port_range.length) problem ||= '目标端口是空的'
      for (const port of parsed.port) if (!(match.port ??= []).includes(port)) match.port.push(port)
      push('port_range', parsed.port_range)
    } else if (cond.t === 'network') {
      if (!cond.nets.length) problem ||= '网络没有选'
      push('network', cond.nets)
    } else {
      const values = lines(cond.text)
      if (!values.length) problem ||= '客户端是空的'
      push('client', values)
      if (cond.invert) match.client_invert = true
    }
  }
  if (!form.conds.length) problem ||= '至少要有一个条件'
  if (match.client && (match.ip_cidr || match.ip_ruleset)) problem ||= '有客户端条件时不能带 IP 部分'
  if ((match.port || match.port_range || match.network) && (match.client || form.conds.some(takesNames))) problem ||= TRANSPORT_WITH_NAMES
  return { match, problem }
})

// The DNS side applies to a rule that meets names: one with name conditions, or one of clients
// alone (it meets every name those clients ask).
const hasNamePart = computed(() => {
  const match = built.value.match
  return !!(match.domain || match.suffix || match.keyword || match.regex || match.ruleset || (match.client && !match.ip_cidr && !match.ip_ruleset))
})
const action = computed<Schemas['Action']>(() => (form.action === 'proxy' ? { type: 'proxy', group_id: form.group } : { type: form.action }))
const preview = computed(() => ({
  match: built.value.match,
  action: action.value,
  dns: form.action === 'direct' && form.dns ? form.dns : undefined,
  cache: form.action === 'direct' ? form.cache : undefined
}))

function reload() {
  error.value = ''
  fill(rules.value.find((item) => item.id === id.value))
}

async function save(overwrite = false) {
  error.value = ''
  if (overwrite) {
    formVersion.value = rulesVersion.value
    conflict.value = null
  }
  if (built.value.problem) {
    error.value = built.value.problem
    return
  }
  if (hasClient.value && form.action === 'proxy') {
    error.value = '有客户端条件时不能代理'
    return
  }
  // A direct rule keeps its upstream group and cache switch even while it has no name part
  // (they are hidden then, and apply again once it has one).
  const direct = form.action === 'direct'
  const body = {
    enabled: form.enabled,
    remark: form.remark.trim(),
    match: built.value.match,
    action: action.value,
    ...(direct && form.dns ? { dns: form.dns } : {}),
    ...(direct && !form.cache ? { cache: false } : {}),
    version: formVersion.value
  }
  saving.value = true
  try {
    if (id.value) await call(client.PUT('/rules/{id}', { params: { path: { id: id.value } }, body }))
    else await call(client.POST('/rules', { body }))
    toast('ok', '已保存')
    await router.push('/rules')
  } catch (failure) {
    if (failure instanceof ApiError && failure.status === 409 && failure.body?.version !== undefined) {
      await loadRules().catch(() => {})
      if (!id.value) {
        // A new rule overwrites nothing: the next save carries the current version.
        formVersion.value = rulesVersion.value
        error.value = '规则表已在别处修改，已载入最新版本，请再保存一次（409）'
      } else {
        conflict.value = rules.value.find((item) => item.id === id.value) ?? null
        if (!conflict.value) error.value = '这条规则已在别处删除（409）'
      }
    } else {
      error.value = describe(failure)
    }
  } finally {
    saving.value = false
    loadRulesets().catch(() => {})
    refreshStatus().catch(() => {})
  }
}

const kindLabel: Record<Kind, string> = { source: '内置规则集', set: '自定义规则集', domain: '自定义条件', ip: '自定义条件', client: '自定义条件', port: '自定义条件', network: '自定义条件' }
</script>

<template>
  <div v-if="loaded" class="split3">
    <div class="grid" style="gap: 16px">
      <div class="card grid" style="gap: 12px">
        <h2>基本信息</h2>
        <div class="row">
          <div class="field" style="flex: 1">
            <label for="rremark">备注</label>
            <input id="rremark" v-model="form.remark" class="inp" autocomplete="off" />
          </div>
          <div class="field">
            <span class="label">启用</span>
            <button class="sw" type="button" :class="{ on: form.enabled }" :aria-pressed="form.enabled" aria-label="启用" @click="form.enabled = !form.enabled"></button>
          </div>
        </div>
      </div>

      <div class="card grid" style="gap: 12px">
        <div class="row">
          <h2>条件</h2>
          <span class="sp"></span>
          <div class="addbar">
            <button class="btn sm" type="button" @click="add('source')">＋ 内置规则集</button>
            <button class="btn sm" type="button" @click="add('set')">＋ 自定义规则集</button>
            <button class="btn sm" type="button" @click="add(hasTransport ? 'ip' : 'domain')">＋ 自定义条件</button>
            <button class="btn sm ghost" type="button" @click="pasting = !pasting">粘贴 sing-box 规则</button>
          </div>
        </div>

        <div v-if="pasting" class="cond">
          <textarea v-model="pasted" class="inp mono" placeholder='{"ip_cidr": ["91.108.4.0/22"], "port": [443], "network": "tcp"}' aria-label="sing-box 规则"></textarea>
          <div v-if="pasteError" class="err">{{ pasteError }}</div>
          <div class="row" style="justify-content: flex-end">
            <button class="btn sm" type="button" @click="pasting = false">取消</button>
            <button class="btn sm pri" type="button" :disabled="!pasted.trim()" @click="importRule">导入</button>
          </div>
        </div>

        <template v-for="{ cond, index, joint } in ordered" :key="cond.key">
        <div v-if="joint" class="hint" style="text-align: center">{{ joint }}</div>
        <div class="cond">
          <div class="row" style="gap: 8px">
            <span class="pill acc">{{ kindLabel[cond.t] }}</span>
            <select
              v-if="['domain', 'ip', 'client', 'port', 'network'].includes(cond.t)"
              class="inp sm"
              :value="cond.t"
              :aria-label="`条件类型 ${index + 1}`"
              @change="setKind(cond, ($event.target as HTMLSelectElement).value as Kind)"
            >
              <option value="domain" :disabled="!kindOk(cond, 'domain')">域名</option>
              <option value="ip" :disabled="!kindOk(cond, 'ip')">目标 IP 网段</option>
              <option value="port" :disabled="!kindOk(cond, 'port')">目标端口</option>
              <option value="network" :disabled="!kindOk(cond, 'network')">网络</option>
              <option value="client" :disabled="!kindOk(cond, 'client')">客户端</option>
            </select>
            <span class="sp"></span>
            <button class="ico" type="button" :aria-label="`删除条件 ${index + 1}`" @click="form.conds.splice(index, 1)">✕</button>
          </div>

          <template v-if="cond.t === 'source'">
            <SourcePicker v-if="!cond.ref" :label="`搜索内置规则集 ${index + 1}`" :names-only="hasClient" :ips-only="hasTransport" @pick="pickSource(cond, $event)" />
            <div v-else class="row" style="gap: 8px">
              <span>{{ cond.label }}</span>
              <span class="tag">{{ cond.provider }}</span>
              <button class="btn sm ghost" type="button" @click="cond.ref = ''">更换</button>
              <span class="sp"></span>
              <div class="seg sm">
                <button v-for="item in [['domain', '域名'], ['ip', 'IP'], ['all', '全部']] as const" :key="item[0]" type="button" :class="{ on: cond.part === item[0] }" :disabled="!partOk(cond, item[0])" @click="cond.part = item[0]">
                  {{ item[1] }}
                </button>
              </div>
            </div>
          </template>

          <template v-if="cond.t === 'set'">
            <div class="row" style="gap: 8px">
              <select class="inp" style="flex: 1; width: auto" :value="cond.ref" :aria-label="`自定义规则集 ${index + 1}`" @change="pickSet(cond, ($event.target as HTMLSelectElement).value)">
                <option value="" disabled>选择规则集</option>
                <optgroup label="远程订阅">
                  <option v-for="set in customSets.filter((item) => item.type === 'remote')" :key="set.id" :value="set.id">{{ set.name }} · {{ set.rule_count + (set.ip_count ?? 0) }} 条</option>
                </optgroup>
                <optgroup label="本地列表">
                  <option v-for="set in customSets.filter((item) => item.type === 'local')" :key="set.id" :value="set.id">{{ set.name }} · {{ set.rule_count }} 条</option>
                </optgroup>
                <option value="__new">＋ 新建订阅…</option>
              </select>
              <div v-if="cond.ref && cond.ref !== '__new'" class="seg sm">
                <button v-for="item in [['domain', '域名'], ['ip', 'IP'], ['all', '全部']] as const" :key="item[0]" type="button" :class="{ on: cond.part === item[0] }" :disabled="!partOk(cond, item[0])" @click="cond.part = item[0]">
                  {{ item[1] }}
                </button>
              </div>
            </div>
            <div v-if="cond.ref === '__new'" class="grid" style="gap: 8px">
              <div class="grid" style="grid-template-columns: minmax(0, 1fr) minmax(0, 2fr) auto; gap: 8px">
                <input v-model="cond.sub.name" class="inp" placeholder="名称" aria-label="订阅名称" autocomplete="off" />
                <input v-model="cond.sub.url" class="inp mono" placeholder="https://…" aria-label="订阅 URL" autocomplete="off" />
                <select v-model="cond.sub.format" class="inp sm" aria-label="格式">
                  <option v-for="format in FORMATS" :key="format" :value="format">{{ format }}</option>
                </select>
              </div>
              <div class="row">
                <input v-if="cond.sub.format === 'dat'" v-model="cond.sub.category" class="inp sm mono" placeholder="分类，例如 cn" aria-label="分类" autocomplete="off" />
                <span class="sp"></span>
                <button class="btn sm pri" type="button" :disabled="!cond.sub.url.trim() || creating" @click="createSub(cond)">创建并选用</button>
              </div>
            </div>
          </template>

          <template v-if="cond.t === 'domain'">
            <textarea v-model="cond.text" class="inp" placeholder="domain:google.com&#10;full:www.example.com&#10;keyword:tracker&#10;regexp:^ads?\d*\." :aria-label="`域名 ${index + 1}`"></textarea>
            <div class="hint" :style="{ color: parseNames(cond.text).bad.length ? 'var(--bad)' : '' }">每行一个，命中任一即可 · {{ nameStats(cond.text) }}</div>
          </template>
          <template v-if="cond.t === 'ip'">
            <textarea v-model="cond.text" class="inp" placeholder="91.108.4.0/22&#10;2001:b28:f23d::/48" :aria-label="`目标 IP 网段 ${index + 1}`"></textarea>
          </template>
          <template v-if="cond.t === 'port'">
            <textarea v-model="cond.text" class="inp mono" placeholder="443&#10;8000-9000" :aria-label="`目标端口 ${index + 1}`"></textarea>
            <div v-if="parsePorts(cond.text).bad.length" class="hint" style="color: var(--bad)">无法识别：{{ parsePorts(cond.text).bad.slice(0, 3).join('、') }}</div>
          </template>
          <template v-if="cond.t === 'network'">
            <div class="seg sm" style="align-self: flex-start">
              <button v-for="network in ['tcp', 'udp']" :key="network" type="button" :class="{ on: cond.nets.includes(network) }" :aria-pressed="cond.nets.includes(network)" @click="toggleNet(cond, network)">
                {{ network.toUpperCase() }}
              </button>
            </div>
          </template>
          <template v-if="cond.t === 'client'">
            <textarea v-model="cond.text" class="inp" placeholder="192.168.1.50&#10;192.168.1.0/24" :aria-label="`客户端 ${index + 1}`"></textarea>
            <div class="seg sm" style="align-self: flex-start">
              <button type="button" :class="{ on: !cond.invert }" @click="cond.invert = false">名单内的客户端</button>
              <button type="button" :class="{ on: cond.invert }" @click="cond.invert = true">名单外的客户端</button>
            </div>
          </template>
        </div>
        </template>
      </div>

      <div class="card grid" style="gap: 12px">
        <h2>动作</h2>
        <div class="row">
          <div class="seg">
            <button type="button" :class="{ on: form.action === 'proxy' }" :disabled="hasClient" @click="form.action = 'proxy'">代理</button>
            <button type="button" :class="{ on: form.action === 'direct' }" @click="form.action = 'direct'">直连</button>
            <button type="button" :class="{ on: form.action === 'block' }" @click="form.action = 'block'">屏蔽</button>
          </div>
          <select v-if="form.action === 'proxy'" v-model="form.group" class="inp" style="width: auto" aria-label="代理到">
            <option v-for="target in proxyTargets" :key="target.id" :value="target.id">{{ target.name }}</option>
          </select>
        </div>
        <div v-if="form.action === 'direct' && hasNamePart" class="field">
          <label for="rdns">DNS 上游组</label>
          <select id="rdns" v-model="form.dns" class="inp">
            <option value="">默认（国内）</option>
            <option v-for="group in upstreamGroups" :key="group.tag" :value="group.tag">
              {{ group.name ?? group.tag }}{{ group.builtin ? '' : '（自定义）' }} · {{ group.upstreams.filter((item) => item.enabled !== false).length }} 个上游
            </option>
          </select>
        </div>
        <div v-if="form.action === 'direct' && hasNamePart" class="row">
          <div style="flex: 1">缓存</div>
          <button class="sw" type="button" :class="{ on: form.cache }" :aria-pressed="form.cache" aria-label="缓存" @click="form.cache = !form.cache"></button>
        </div>
      </div>
    </div>

    <div class="card grid sticky" style="gap: 10px">
      <h2>规则摘要</h2>
      <div class="tile">
        <div class="k">条件</div>
        <div class="v" style="font-size: 13px">{{ summary(built.match) || '—' }}</div>
      </div>
      <div class="tile">
        <div class="k">动作</div>
        <div class="v">{{ actionLabel(action) }}</div>
      </div>
      <div v-if="form.action !== 'block'" class="tile">
        <div class="k">DNS</div>
        <div class="v">{{ dnsLabel(preview) || '—' }}</div>
      </div>
      <template v-if="conflict">
        <div class="err">规则已在别处修改（409）。现在保存的是：</div>
        <div class="tile" style="font-size: 12.5px">
          <div>{{ conflict.remark || conflict.id }}{{ conflict.enabled ? '' : '（停用）' }}</div>
          <div class="t2">{{ summary(conflict.match) }}</div>
          <div class="t2">{{ actionLabel(conflict.action) }}{{ dnsLabel(conflict) ? ` · ${dnsLabel(conflict)}` : '' }}</div>
        </div>
        <div class="row" style="justify-content: flex-end">
          <button class="btn" type="button" @click="reload">载入最新内容</button>
          <button class="btn red" type="button" :disabled="saving" @click="save(true)">仍然保存</button>
        </div>
      </template>
      <div v-if="error" class="err">{{ error }}</div>
      <div v-if="!conflict" class="row" style="justify-content: flex-end">
        <button class="btn" type="button" @click="router.push('/rules')">取消</button>
        <button class="btn pri" type="button" :disabled="saving" @click="save()">保存</button>
      </div>
    </div>
  </div>
  <div v-else-if="error" class="row">
    <div class="err" style="flex: 1">{{ error }}</div>
    <button class="btn" type="button" @click="load">重试</button>
  </div>
</template>
