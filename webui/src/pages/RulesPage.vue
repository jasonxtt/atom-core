<script setup lang="ts">
import { computed, nextTick, onMounted, ref } from 'vue'
import { RouterLink, useRouter } from 'vue-router'
import draggable from 'vuedraggable'
import { ApiError, call, client, describe, type Schemas } from '../api/client'
import AppModal from '../components/AppModal.vue'
import RulesTabs from '../components/RulesTabs.vue'
import { FINAL_NAME, loadProxy } from '../composables/proxy'
import { dnsLabel, groupName, upstreamName, loadRules, loadRulesets, loadUpstreams, proxyTargets, rules, rulesVersion, summary, type Rule } from '../composables/rules'
import { refreshStatus } from '../composables/status'
import { toast } from '../composables/toast'
import { chainNames, directiveText, KIND_LABEL, viaLabel } from '../dryrun'
import { originalBranches } from '../original'

const router = useRouter()
const error = ref('')

// The original judgement under the last rule (DNS only; the switches it shows come from `GET dns`).
const dns = ref<Schemas['Dns'] | null>(null)
const branches = computed(() => (dns.value ? originalBranches(dns.value, FINAL_NAME) : []))
const originalOpen = ref(false)

onMounted(async () => {
  const results = await Promise.allSettled([
    loadRules(),
    loadRulesets(),
    loadUpstreams(),
    loadProxy(),
    call(client.GET('/dns')).then((value) => (dns.value = value))
  ])
  const failed = results.find((result) => result.status === 'rejected')
  error.value = failed ? describe((failed as PromiseRejectedResult).reason) : ''
})

/** A write refused for a stale version reloads the table; other failures are shown. */
async function failed(failure: unknown) {
  if (failure instanceof ApiError && failure.status === 409 && failure.body?.version !== undefined) {
    await loadRules().catch(() => {})
    toast('warn', '规则表已在别处修改，已载入最新内容，请重试（409）')
  } else {
    toast('bad', describe(failure))
  }
}

// ---- dry run --------------------------------------------------------------------
type DryRun = Schemas['DryRun']
const testDomain = ref('')
const testClient = ref('')
const testType = ref<'A' | 'AAAA'>('A')
const testing = ref(false)
const testError = ref('')
const dry = ref<DryRun | null>(null)
const hitId = computed(() => dry.value?.steps.find((step) => step.key === 'rules')?.rule?.id ?? '')
const hitOriginal = computed(() => !!dry.value?.branch)
const conclusion = computed(() => dry.value?.conclusion)
const chain = computed(() => chainNames(conclusion.value?.chain ?? [], FINAL_NAME))
async function test() {
  const domain = testDomain.value.trim()
  if (!domain || testing.value) return
  testing.value = true
  try {
    const body: { domain: string; client?: string; qtype: 'A' | 'AAAA' } = { domain, qtype: testType.value }
    if (testClient.value.trim()) body.client = testClient.value.trim()
    dry.value = await call(client.POST('/rules/dryrun', { body }))
    testError.value = ''
    if (dry.value.branch) originalOpen.value = true
  } catch (failure) {
    dry.value = null
    testError.value = describe(failure)
  } finally {
    testing.value = false
  }
}
const resultLabel = (result: string) => (result === 'hit' ? '命中' : '未命中')
const ruleStatus: Record<string, string> = { hit: '命中', miss: '未命中', off: '停用', singbox: '只在 sing-box' }

// ---- edits in the list ---------------------------------------------------------------
/** The body that replaces `rule` (direct-only fields only on a direct rule). */
function replacement(rule: Rule, change: Partial<Pick<Rule, 'enabled' | 'action'>>) {
  const next = { ...rule, ...change }
  return {
    enabled: next.enabled,
    remark: next.remark,
    match: next.match,
    action: next.action,
    ...(next.action.type === 'direct' ? { ...(next.dns ? { dns: next.dns } : {}), ...(next.cache === false ? { cache: false } : {}) } : {}),
    version: rulesVersion.value
  }
}

// One write at a time: each carries the table's version, so a second one sent before the first
// answered would be refused (or answered out of order).
const busy = ref('')
async function change(rule: Rule, edit: Partial<Pick<Rule, 'enabled' | 'action'>>) {
  if (busy.value) return
  busy.value = rule.id
  try {
    const answer = await call(client.PUT('/rules/{id}', { params: { path: { id: rule.id } }, body: replacement(rule, edit) }))
    rulesVersion.value = answer.version
    const index = rules.value.findIndex((item) => item.id === rule.id)
    if (index >= 0) rules.value[index] = answer.rule
  } catch (failure) {
    await failed(failure)
  } finally {
    busy.value = ''
    refreshStatus().catch(() => {})
  }
}

const actionKey = (rule: Rule) => (rule.action.type === 'proxy' ? `proxy:${rule.action.group_id}` : rule.action.type)
function setAction(rule: Rule, key: string) {
  const action: Schemas['Action'] = key.startsWith('proxy:') ? { type: 'proxy', group_id: key.slice(6) } : { type: key as 'direct' | 'block' }
  void change(rule, { action })
}

async function moved(event: { newIndex: number; oldIndex: number }) {
  if (event.newIndex === event.oldIndex) return
  const list = rules.value
  const id = list[event.newIndex].id
  const body: { id: string; version: number; before_id?: string; after_id?: string } = { id, version: rulesVersion.value }
  if (event.newIndex + 1 < list.length) body.before_id = list[event.newIndex + 1].id
  else body.after_id = list[event.newIndex - 1].id
  busy.value = id
  await send(body)
  busy.value = ''
}

/** The keyboard way to move: the arrows on a rule's handle move it one place. */
async function nudge(index: number, step: -1 | 1) {
  const list = rules.value
  const target = index + step
  if (busy.value || target < 0 || target >= list.length) return
  const id = list[index].id
  const neighbour = list[target].id
  const body = { id, version: rulesVersion.value, ...(step < 0 ? { before_id: neighbour } : { after_id: neighbour }) }
  busy.value = id
  await send(body)
  busy.value = ''
  // Focus follows the rule to its new place.
  await nextTick()
  const handle = document.querySelector<HTMLButtonElement>(`[data-handle="${id}"]`)
  handle?.focus()
}

async function send(body: { id: string; version: number; before_id?: string; after_id?: string }) {
  try {
    const answer = await call(client.POST('/rules/move', { body }))
    rules.value = answer.rules
    rulesVersion.value = answer.version
  } catch (failure) {
    await failed(failure)
    await loadRules().catch(() => {})
  } finally {
    refreshStatus().catch(() => {})
  }
}

const removing = ref<Rule | null>(null)
async function remove() {
  const rule = removing.value
  if (!rule || busy.value) return
  busy.value = rule.id
  try {
    const answer = await call(client.DELETE('/rules/{id}', { params: { path: { id: rule.id }, query: { version: rulesVersion.value } } }))
    rulesVersion.value = answer.version
    rules.value = rules.value.filter((item) => item.id !== rule.id)
    toast('ok', '已删除')
  } catch (failure) {
    await failed(failure)
  } finally {
    removing.value = null
    busy.value = ''
    refreshStatus().catch(() => {})
  }
}
</script>

<template>
  <RulesTabs />
  <div v-if="error" class="err">{{ error }}</div>
  <div class="card">
    <div class="hd"><h2>测试域名</h2></div>
    <form class="row" @submit.prevent="test">
      <input v-model="testDomain" class="inp mono" style="flex: 2; min-width: 180px" placeholder="例如 www.netflix.com" aria-label="测试的域名" autocomplete="off" />
      <input v-model="testClient" class="inp mono" style="flex: 1; min-width: 140px" placeholder="客户端 IP（可选）" aria-label="客户端 IP" autocomplete="off" />
      <select v-model="testType" class="inp" style="flex: none; width: 88px" aria-label="查询类型">
        <option value="A">A</option>
        <option value="AAAA">AAAA</option>
      </select>
      <button class="btn pri" type="submit" :disabled="testing">{{ testing ? '测试中…' : '测试' }}</button>
    </form>
    <div v-if="testError" class="err" style="margin-top: 10px">{{ testError }}</div>
    <template v-if="dry && conclusion">
      <div class="dry-end">
        <div class="dry-kind">
          <span class="pill" :class="{ direct: 'ok', proxy: 'acc', block: 'bad', empty: 'idle', fail: 'bad' }[conclusion.kind]">{{ KIND_LABEL[conclusion.kind] }}</span>
          <span class="t2">{{ viaLabel(conclusion.via) }}<template v-if="conclusion.rule"> · {{ conclusion.rule.remark || conclusion.rule.id }}</template></span>
        </div>
        <div class="kv">
          <template v-if="conclusion.kind === 'proxy'">
            <span>出口</span>
            <span v-if="chain.length" class="dry-chain"><template v-for="(name, i) in chain" :key="i"><span v-if="i" class="orig-arrow" aria-hidden="true">→</span><span>{{ name }}</span></template></span>
            <span v-else>{{ groupName(conclusion.outbound ?? '') }}<span v-if="conclusion.chain_error" class="t2"> · {{ conclusion.chain_error }}</span></span>
            <span>指令</span><span class="mono">FakeIP · {{ directiveText(conclusion.directive, groupName) }}</span>
          </template>
          <template v-if="conclusion.kind === 'direct'">
            <template v-if="conclusion.via === 'rewrite'">
              <span>重写</span><span class="mono">{{ conclusion.detail }}</span>
              <template v-if="conclusion.ips"><span>地址</span><span class="mono">{{ conclusion.ips.join('，') }}</span></template>
            </template>
            <template v-else>
              <span>上游</span><span>{{ upstreamName(conclusion.upstream) }}<span v-if="conclusion.entry" class="t2"> · {{ conclusion.entry }}</span><span v-if="conclusion.ecs" class="t2 mono"> · ECS {{ conclusion.ecs }}</span></span>
              <span>地址</span><span class="mono">{{ (conclusion.ips ?? []).join('，') || '—' }}</span>
            </template>
          </template>
          <template v-if="conclusion.kind === 'empty' || conclusion.kind === 'fail'">
            <span>应答</span><span class="mono">{{ conclusion.detail || conclusion.rcode || 'NOERROR' }}</span>
          </template>
          <template v-if="conclusion.caches"><span>缓存</span><span>{{ conclusion.caches.length ? conclusion.caches.join('，') : '不缓存' }}</span></template>
          <span>绑定</span>
          <span>
            <span class="mono">{{ directiveText(dry.binding.recorded, groupName) }}</span>
            <span v-if="!dry.binding.match" class="pill warn" style="margin-left: 6px">和推演不一致 · 客户端还没重新查询</span>
          </span>
        </div>
      </div>
      <ol class="dry-steps">
        <li v-for="step in dry.steps" :key="step.key" :class="{ hit: step.result === 'hit' }">
          <span class="dry-name">{{ step.name }}</span>
          <span class="pill" :class="step.result === 'hit' ? 'acc' : 'idle'">{{ resultLabel(step.result) }}</span>
          <span class="dry-detail">
            {{ step.detail }}
            <template v-if="step.probe">
              <span class="t2"> · {{ upstreamName(step.probe.upstream) }}<template v-if="step.probe.ecs"> · ECS {{ step.probe.ecs }}</template> · <span class="mono">{{ step.probe.ips.join('，') || step.probe.rcode || step.probe.error }}</span></span>
            </template>
            <span v-if="step.would_learn?.length" class="t2"> · 不学习：{{ step.would_learn.join('，') }}</span>
            <details v-if="step.rules && step.rules.some((rule) => rule.status !== 'hit')" class="dry-rules">
              <summary class="t2">其余 {{ step.rules.filter((rule) => rule.status !== 'hit').length }} 条</summary>
              <ul>
                <li v-for="rule in step.rules.filter((item) => item.status !== 'hit')" :key="rule.id" class="t2">{{ rule.index + 1 }}. {{ rule.remark || rule.id }} · {{ ruleStatus[rule.status] }}</li>
              </ul>
            </details>
          </span>
        </li>
      </ol>
    </template>
  </div>
  <div class="card">
    <div class="hd">
      <h2>规则列表</h2>
      <span class="tag">{{ rules.length }}</span>
      <span class="sp"></span>
      <button class="btn pri" type="button" @click="router.push('/rules/new')">＋ 新建规则</button>
    </div>
    <draggable
      v-model="rules"
      item-key="id"
      class="list"
      handle=".handle"
      :disabled="!!busy"
      :animation="180"
      :force-fallback="true"
      :fallback-on-body="true"
      :fallback-tolerance="4"
      ghost-class="s-ghost"
      chosen-class="s-chosen"
      fallback-class="s-fallback"
      @end="moved"
    >
      <template #item="{ element: rule, index }">
        <div class="li" :class="{ off: !rule.enabled, hit: hitId === rule.id }">
          <button
            type="button"
            class="handle"
            :data-handle="rule.id"
            :aria-label="`移动：${rule.remark || rule.id}（第 ${index + 1} 条，上下方向键移动）`"
            title="拖动排序"
            @keydown.up.prevent="nudge(index, -1)"
            @keydown.down.prevent="nudge(index, 1)"
          >⠿</button>
          <span class="idx tnum">{{ index + 1 }}</span>
          <div style="min-width: 0">
            <div>{{ rule.remark || rule.id }}</div>
            <div class="sum">{{ summary(rule.match) }}</div>
          </div>
          <span class="dnstag">{{ dnsLabel(rule) }}</span>
          <button
            class="sw"
            type="button"
            :class="{ on: rule.enabled }"
            :aria-label="`${rule.enabled ? '停用' : '启用'}：${rule.remark || rule.id}`"
            :aria-pressed="rule.enabled"
            :disabled="!!busy"
            @click="change(rule, { enabled: !rule.enabled })"
          ></button>
          <select class="inp act" :value="actionKey(rule)" :aria-label="`动作：${rule.remark || rule.id}`" :disabled="!!busy" @change="setAction(rule, ($event.target as HTMLSelectElement).value)">
            <option v-for="target in proxyTargets" :key="target.id" :value="`proxy:${target.id}`" :disabled="!!rule.match.client?.length">代理 → {{ target.name }}</option>
            <option value="direct">直连</option>
            <option value="block">屏蔽</option>
          </select>
          <div class="ops row" style="gap: 0">
            <button class="ico" type="button" aria-label="编辑" title="编辑" @click="router.push(`/rules/${rule.id}`)">
              <svg viewBox="0 0 24 24"><path d="M4 20h4L19 9l-4-4L4 16z" /></svg>
            </button>
            <button class="ico" type="button" aria-label="删除" title="删除" style="color: var(--bad)" @click="removing = rule">
              <svg viewBox="0 0 24 24"><path d="M5 7h14M9 7V4h6v3M7 7l1 13h8l1-13" /></svg>
            </button>
          </div>
        </div>
      </template>
    </draggable>
    <div class="li orig" :class="{ hit: hitOriginal }">
      <span class="handle" aria-hidden="true">⠿</span>
      <span class="idx" aria-hidden="true">—</span>
      <div style="min-width: 0">
        <button type="button" class="orig-hd" :aria-expanded="originalOpen" aria-controls="orig-branches" @click="originalOpen = !originalOpen">
          未命中以上规则<span class="orig-chev" aria-hidden="true">{{ originalOpen ? '▾' : '▸' }}</span>
        </button>
        <div class="sum">原判断</div>
        <ul v-if="originalOpen" id="orig-branches" class="orig-list">
          <li v-for="branch in branches" :key="branch.key" :class="{ off: branch.off, hit: dry?.branch === branch.key }">
            <span><RouterLink :to="branch.to">{{ branch.name }}</RouterLink><span v-if="branch.off" class="tag">关</span></span>
            <span class="orig-arrow" aria-hidden="true">→</span>
            <span class="orig-res"><span v-for="item in branch.result" :key="item">{{ item }}</span></span>
          </li>
        </ul>
      </div>
      <span class="act orig-act">DNS</span>
    </div>
  </div>

  <AppModal v-if="removing" :title="`删除规则「${removing.remark || removing.id}」`" @close="removing = null">
    <div class="t2">{{ summary(removing.match) }}</div>
    <template #footer>
      <button class="btn" type="button" @click="removing = null">取消</button>
      <button class="btn red" type="button" :disabled="!!busy" @click="remove">删除</button>
    </template>
  </AppModal>
</template>
