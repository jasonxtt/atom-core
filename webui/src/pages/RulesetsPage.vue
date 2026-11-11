<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ApiError, call, client, describe } from '../api/client'
import AppModal from '../components/AppModal.vue'
import RulesTabs from '../components/RulesTabs.vue'
import RulesetModal from '../components/RulesetModal.vue'
import { builtins, loadRules, loadRulesets, rules, rulesets, summary, type Builtin, type Rule, type Ruleset } from '../composables/rules'
import { refreshStatus } from '../composables/status'
import { toast } from '../composables/toast'
import { ago } from '../format'

const error = ref('')
const catalog = ref<{ size: number; updated_at: number } | null>(null)

async function loadCatalog() {
  const answer = await call(client.GET('/catalog', { params: { query: { limit: 1 } } }))
  catalog.value = { size: answer.size, updated_at: answer.updated_at }
}

onMounted(async () => {
  const results = await Promise.allSettled([loadRulesets(), loadRules(), loadCatalog()])
  const failed = results.find((result) => result.status === 'rejected')
  error.value = failed ? describe((failed as PromiseRejectedResult).reason) : ''
})

const custom = computed(() => rulesets.value.filter((set) => set.type !== 'catalog'))
const used = computed(() => rulesets.value.filter((set) => set.type === 'catalog'))

const counts = (set: Ruleset) => [set.rule_count ? `${set.rule_count} 域名` : '', set.ip_count ? `${set.ip_count} IP` : ''].filter(Boolean).join(' · ') || '0'
const skipped = (set: Ruleset) => Object.values(set.skipped ?? {}).reduce((sum, count) => sum + count, 0)
const skippedText = (set: Ruleset) =>
  Object.entries(set.skipped ?? {})
    .map(([kind, count]) => `${kind} ${count}`)
    .join('、')
const updated = (seconds: number) => (seconds ? ago(seconds) : '—')
const updatedAt = (text: string | undefined) => (text ? ago(Date.parse(text) / 1000) : '—')

// ---- refresh / sync -------------------------------------------------------------------
const busy = ref('')
async function refresh(target: Ruleset | Builtin) {
  busy.value = target.id
  try {
    await call(client.POST('/rulesets/{id}/refresh', { params: { path: { id: target.id } } }))
    toast('ok', `已刷新「${target.name}」`)
  } catch (failure) {
    toast('bad', `「${target.name}」${describe(failure)}`)
  } finally {
    busy.value = ''
    await loadRulesets().catch(() => {})
    refreshStatus().catch(() => {})
  }
}

async function sync() {
  busy.value = 'catalog'
  try {
    const answer = await call(client.POST('/catalog/sync'))
    catalog.value = answer
    toast('ok', `目录已同步，共 ${answer.size} 项`)
  } catch (failure) {
    toast('bad', describe(failure))
  } finally {
    busy.value = ''
  }
}

// ---- dialogs -------------------------------------------------------------------------
const editing = ref<{ mode: 'new' | 'edit' | 'url'; target?: Ruleset | Builtin } | null>(null)

// Deleting: a set rules name asks again, listing them (a rule left without a name or IP
// condition is deleted with it).
const removing = ref<{ target: Ruleset | Builtin; rules: Rule[] | null } | null>(null)
function leftOver(rule: Rule, id: string) {
  const match = rule.match
  const sets = (match.ruleset ?? []).filter((item) => item !== id)
  const ipSets = (match.ip_ruleset ?? []).filter((item) => item !== id)
  return !!(match.domain?.length || match.suffix?.length || match.keyword?.length || match.regex?.length || match.ip_cidr?.length || sets.length || ipSets.length)
}
async function remove(confirm: boolean) {
  const current = removing.value
  if (!current) return
  busy.value = current.target.id
  try {
    await call(client.DELETE('/rulesets/{id}', { params: { path: { id: current.target.id }, query: confirm ? { confirm: true } : {} } }))
    toast('ok', `已删除「${current.target.name}」`)
    removing.value = null
  } catch (failure) {
    const ids = failure instanceof ApiError && failure.status === 409 ? failure.body?.rules : undefined
    if (ids?.length && !confirm) {
      await loadRules().catch(() => {})
      current.rules = rules.value.filter((rule) => ids.includes(rule.id))
    } else {
      removing.value = null
      toast('bad', describe(failure))
    }
  } finally {
    busy.value = ''
    await Promise.allSettled([loadRulesets(), loadRules()])
    refreshStatus().catch(() => {})
  }
}
</script>

<template>
  <RulesTabs />
  <div v-if="error" class="err">{{ error }}</div>

  <div class="card">
    <div class="hd">
      <h2>自定义规则集</h2>
      <span class="sp"></span>
      <button class="btn pri" type="button" @click="editing = { mode: 'new' }">＋ 新建</button>
    </div>
    <div class="tblwrap">
      <table>
        <thead>
          <tr><th>名称</th><th>类型</th><th>来源</th><th>条目</th><th>更新</th><th>状态</th><th></th></tr>
        </thead>
        <tbody>
          <tr v-for="set in custom" :key="set.id">
            <td>{{ set.name }}</td>
            <td class="t2">{{ set.type === 'remote' ? '远程订阅' : '本地列表' }}</td>
            <td class="mono t2" style="max-width: 300px; overflow: hidden; text-overflow: ellipsis" :title="set.url">{{ set.type === 'remote' ? `${set.url} · ${set.format || 'auto'}` : '—' }}</td>
            <td class="tnum">{{ counts(set) }}</td>
            <td class="t2">{{ updated(set.updated_at) }}</td>
            <td>
              <span v-if="set.last_error" class="pill bad" :title="set.last_error">下载失败</span>
              <span v-else-if="skipped(set)" class="pill warn" :title="skippedText(set)">跳过 {{ skipped(set) }}</span>
              <span v-else class="pill ok">正常</span>
            </td>
            <td style="text-align: right; white-space: nowrap">
              <button class="btn sm" type="button" @click="editing = { mode: 'edit', target: set }">编辑</button>
              <button v-if="set.type === 'remote'" class="btn sm" type="button" :disabled="busy === set.id" @click="refresh(set)">刷新</button>
              <button class="btn sm danger" type="button" @click="removing = { target: set, rules: null }">删除</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

  <div class="card">
    <div class="hd">
      <h2>规则源目录</h2>
      <span class="sp"></span>
      <button class="btn sm" type="button" :disabled="busy === 'catalog'" @click="sync">立即同步</button>
    </div>
    <div class="grid g2" style="gap: 8px">
      <div class="tile">
        <div class="k">MetaCubeX / meta-rules-dat · blackmatrix7 / ios_rule_script</div>
        <div class="v">{{ catalog ? `${catalog.size} 项` : '—' }}</div>
        <div class="s">{{ catalog ? `索引 ${updated(catalog.updated_at)}` : '' }}</div>
      </div>
    </div>
    <div v-if="used.length" class="tblwrap" style="margin-top: 12px">
      <table>
        <thead>
          <tr><th>规则里用到的</th><th>条目</th><th>未使用</th><th>更新</th><th>状态</th><th></th></tr>
        </thead>
        <tbody>
          <tr v-for="set in used" :key="set.id">
            <td>{{ set.name }}</td>
            <td class="tnum">{{ counts(set) }}</td>
            <td class="t2" :title="skippedText(set)">{{ skipped(set) || '—' }}</td>
            <td class="t2">{{ updated(set.updated_at) }}</td>
            <td>
              <span v-if="set.last_error" class="pill bad" :title="set.last_error">下载失败</span>
              <span v-else class="pill ok">正常</span>
            </td>
            <td style="text-align: right"><button class="btn sm" type="button" :disabled="busy === set.id" @click="refresh(set)">刷新</button></td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

  <div class="card">
    <div class="hd"><h2>内置</h2></div>
    <div class="tblwrap">
      <table>
        <thead>
          <tr><th>名称</th><th>来源</th><th>更新</th><th></th></tr>
        </thead>
        <tbody>
          <tr v-for="set in builtins" :key="set.id">
            <td>{{ set.name }} <span class="mono t2">{{ set.id }}</span> <span v-if="set.required" class="tag">必需</span></td>
            <td class="mono t2" style="max-width: 340px; overflow: hidden; text-overflow: ellipsis" :title="set.url">{{ set.url ?? '多个来源' }}</td>
            <td class="t2">{{ updatedAt(set.updated) }}</td>
            <td style="text-align: right; white-space: nowrap">
              <button v-if="set.url" class="btn sm" type="button" @click="editing = { mode: 'url', target: set }">编辑 URL</button>
              <button v-if="set.refreshable" class="btn sm" type="button" :disabled="busy === set.id" @click="refresh(set)">刷新</button>
              <button v-if="!set.required" class="btn sm danger" type="button" @click="removing = { target: set, rules: null }">删除</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

  <RulesetModal v-if="editing" :mode="editing.mode" :target="editing.target" @close="editing = null" />
  <AppModal v-if="removing" :title="`删除规则集「${removing.target.name}」`" @close="removing = null">
    <template v-if="removing.rules">
      <div class="err">有 {{ removing.rules.length }} 条规则用到它，删除后会从这些规则里去掉这个条件：</div>
      <div class="tile" style="font-size: 12.5px">
        <div v-for="rule in removing.rules" :key="rule.id">
          {{ rule.remark || rule.id }}{{ leftOver(rule, removing.target.id) ? '' : '（整条删除）' }}
          <span class="t2">{{ summary(rule.match) }}</span>
        </div>
      </div>
    </template>
    <template #footer>
      <button class="btn" type="button" @click="removing = null">取消</button>
      <button class="btn red" type="button" :disabled="busy === removing.target.id" @click="remove(!!removing.rules)">{{ removing.rules ? '仍然删除' : '删除' }}</button>
    </template>
  </AppModal>
</template>
