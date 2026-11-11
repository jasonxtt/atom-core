<script setup lang="ts">
import { nextTick, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import draggable from 'vuedraggable'
import { ApiError, call, client, describe, type Schemas } from '../api/client'
import AppModal from '../components/AppModal.vue'
import RulesTabs from '../components/RulesTabs.vue'
import { loadProxy } from '../composables/proxy'
import { actionLabel, dnsLabel, loadRules, loadRulesets, loadUpstreams, proxyTargets, rules, rulesVersion, summary, type Rule } from '../composables/rules'
import { refreshStatus } from '../composables/status'
import { toast } from '../composables/toast'

const router = useRouter()
const error = ref('')

onMounted(async () => {
  const results = await Promise.allSettled([loadRules(), loadRulesets(), loadUpstreams(), loadProxy()])
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

// ---- test -----------------------------------------------------------------------
const testDomain = ref('')
const testClient = ref('')
const testResult = ref('')
const hitId = ref('')
async function test() {
  const domain = testDomain.value.trim()
  if (!domain) return
  try {
    const body: { domain: string; client?: string } = { domain }
    if (testClient.value.trim()) body.client = testClient.value.trim()
    const answer = await call(client.POST('/rules/test', { body }))
    hitId.value = answer.rule?.id ?? ''
    testResult.value =
      answer.matched && answer.rule && answer.index !== undefined
        ? `命中第 ${answer.index + 1} 条「${answer.rule.remark || answer.rule.id}」：${actionLabel(answer.rule.action)}`
        : '没有规则命中，交给原判断'
  } catch (failure) {
    hitId.value = ''
    testResult.value = describe(failure)
  }
}

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

const busy = ref('')
async function change(rule: Rule, edit: Partial<Pick<Rule, 'enabled' | 'action'>>) {
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
  await send(body)
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
  if (!rule) return
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
      <button class="btn pri" type="submit">测试</button>
    </form>
    <div v-if="testResult" class="note" style="margin-top: 10px; color: var(--text)">{{ testResult }}</div>
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
            :disabled="busy === rule.id"
            @click="change(rule, { enabled: !rule.enabled })"
          ></button>
          <select class="inp act" :value="actionKey(rule)" :aria-label="`动作：${rule.remark || rule.id}`" :disabled="busy === rule.id" @change="setAction(rule, ($event.target as HTMLSelectElement).value)">
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
  </div>

  <AppModal v-if="removing" :title="`删除规则「${removing.remark || removing.id}」`" @close="removing = null">
    <div class="t2">{{ summary(removing.match) }}</div>
    <template #footer>
      <button class="btn" type="button" @click="removing = null">取消</button>
      <button class="btn red" type="button" :disabled="!!busy" @click="remove">删除</button>
    </template>
  </AppModal>
</template>
