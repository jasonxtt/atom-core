<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ApiError, call, client, describe, type Schemas } from '../api/client'
import AppModal from '../components/AppModal.vue'
import DnsTabs from '../components/DnsTabs.vue'
import UpstreamModal from '../components/UpstreamModal.vue'
import { loadRules, loadUpstreams, rules, setUpstreamGroups, upstreamGroups } from '../composables/rules'
import { toast } from '../composables/toast'

type Upstream = Schemas['Upstream']
type Group = Schemas['UpstreamGroup']

// Each group is edited in a draft and saved whole (PUT replaces its list).
const drafts = reactive<Record<string, { name: string; upstreams: Upstream[] }>>({})
const error = ref('')
const busy = ref('')

function reset(groups: Group[]) {
  for (const key of Object.keys(drafts)) delete drafts[key]
  for (const group of groups) drafts[group.tag] = { name: group.name, upstreams: group.upstreams.map((item) => ({ ...item })) }
}

async function load() {
  error.value = ''
  try {
    await Promise.all([loadUpstreams(), loadRules()])
    reset(upstreamGroups.value)
  } catch (failure) {
    error.value = describe(failure)
  }
}
onMounted(load)

/** Drops one group's unsaved edits. */
function revert(group: Group) {
  drafts[group.tag] = { name: group.name, upstreams: group.upstreams.map((item) => ({ ...item })) }
}

const dirty = (group: Group) => {
  const draft = drafts[group.tag]
  return !!draft && (draft.name !== group.name || JSON.stringify(draft.upstreams) !== JSON.stringify(group.upstreams))
}
const usedBy = (tag: string) => rules.value.filter((rule) => rule.dns === tag)
const allTags = computed(() => Object.values(drafts).flatMap((draft) => draft.upstreams.map((item) => item.tag)))
const PROTOCOLS: Record<string, string> = { udp: 'UDP', tcp: 'TCP', tls: 'DoT', dot: 'DoT', https: 'DoH', doh: 'DoH', h3: 'DoH3', quic: 'DoQ', doq: 'DoQ' }
const http3 = (upstream: Upstream) => upstream.protocol === 'h3' || (!!upstream.enable_http3 && (upstream.protocol === 'https' || upstream.protocol === 'doh'))
const protocolName = (upstream: Upstream) => (http3(upstream) ? 'DoH3' : (PROTOCOLS[upstream.protocol] ?? upstream.protocol))
/** UDP, DoQ and DoH over HTTP/3 cannot go through the proxy. */
const noProxy = (upstream: Upstream) => ['udp', 'quic', 'doq'].includes(upstream.protocol) || http3(upstream)

/**
 * Applies a write's answer: every group as it is now. The unsaved drafts of the other groups,
 * taken when the answer arrives, are kept (editing waits while a write runs).
 */
function applied(groups: Group[], written: string) {
  const kept = Object.fromEntries(upstreamGroups.value.filter((group) => group.tag !== written && dirty(group)).map((group) => [group.tag, drafts[group.tag]]))
  setUpstreamGroups(groups)
  reset(groups)
  for (const [tag, draft] of Object.entries(kept)) if (drafts[tag]) drafts[tag] = draft
}

async function save(group: Group) {
  const draft = drafts[group.tag]
  if (!draft.upstreams.some((item) => item.enabled !== false)) return toast('bad', `「${group.name}」至少要启用一个上游`)
  busy.value = group.tag
  try {
    const body = { upstreams: draft.upstreams, ...(!group.builtin && draft.name.trim() !== group.name ? { name: draft.name.trim() } : {}) }
    const answer = await call(client.PUT('/upstreams/{tag}', { params: { path: { tag: group.tag } }, body }))
    applied(answer.groups, group.tag)
    toast('ok', `已保存「${draft.name}」`)
  } catch (failure) {
    toast('bad', describe(failure))
  } finally {
    busy.value = ''
  }
}

// ---- restore / delete -----------------------------------------------------------------
const confirming = ref<{ group: Group; kind: 'restore' | 'delete' } | null>(null)
async function confirmed() {
  const current = confirming.value
  if (!current) return
  const { group, kind } = current
  busy.value = group.tag
  try {
    const answer =
      kind === 'restore'
        ? await call(client.PUT('/upstreams/{tag}', { params: { path: { tag: group.tag } }, body: { upstreams: [] } }))
        : await call(client.DELETE('/upstreams/{tag}', { params: { path: { tag: group.tag } } }))
    applied(answer.groups, group.tag)
    toast('ok', kind === 'restore' ? `「${group.name}」已恢复默认` : `已删除「${group.name}」`)
  } catch (failure) {
    const ids = failure instanceof ApiError && failure.status === 409 ? failure.body?.rules : undefined
    toast('bad', ids?.length ? `有 ${ids.length} 条规则使用「${group.name}」，先把它们改用其他上游组` : describe(failure))
  } finally {
    confirming.value = null
    busy.value = ''
  }
}

// ---- the upstream dialog ----------------------------------------------------------------
const editing = ref<{ group?: Group; index: number } | null>(null)
function saveUpstream(upstream: Upstream, name: string) {
  const current = editing.value
  if (!current) return
  if (!current.group) return void createGroup(name, upstream)
  const list = drafts[current.group.tag].upstreams
  if (current.index >= 0) list[current.index] = upstream
  else list.push(upstream)
  editing.value = null
}
function removeUpstream() {
  const current = editing.value
  if (current?.group && current.index >= 0) drafts[current.group.tag].upstreams.splice(current.index, 1)
  editing.value = null
}

async function createGroup(name: string, upstream: Upstream) {
  busy.value = 'new'
  try {
    const answer = await call(client.POST('/upstreams', { body: { name, upstreams: [upstream] } }))
    applied(answer.groups, '')
    toast('ok', `已新建「${name}」`)
    editing.value = null
  } catch (failure) {
    toast('bad', describe(failure))
  } finally {
    busy.value = ''
  }
}
</script>

<template>
  <DnsTabs />
  <div v-if="error" class="err">{{ error }}</div>
  <div class="row">
    <span class="sp"></span>
    <button class="btn pri" type="button" :disabled="!!busy" @click="editing = { index: -1 }">＋ 新建上游组</button>
  </div>
  <div v-for="group in upstreamGroups" :key="group.tag" class="card">
    <fieldset v-if="drafts[group.tag]" class="plain" :disabled="!!busy">
      <div class="hd">
        <input v-if="!group.builtin" v-model="drafts[group.tag].name" class="inp" style="width: 180px" :aria-label="`组名：${group.name}`" autocomplete="off" />
        <h2 v-else>{{ group.name }}</h2>
        <span class="mono t2">{{ group.tag }}</span>
        <span class="tag">{{ group.builtin ? '内置' : '自定义' }}</span>
        <span class="t2">启用 {{ drafts[group.tag].upstreams.filter((item) => item.enabled !== false).length }} 个 · 被 {{ usedBy(group.tag).length }} 条规则使用</span>
        <span class="sp"></span>
        <button v-if="group.builtin && group.customized" class="btn sm" type="button" :disabled="!!busy" @click="confirming = { group, kind: 'restore' }">恢复默认</button>
        <button v-if="!group.builtin" class="btn sm danger" type="button" :disabled="!!busy" @click="confirming = { group, kind: 'delete' }">删除</button>
        <button v-if="dirty(group)" class="btn sm" type="button" :disabled="!!busy" @click="revert(group)">撤销</button>
        <button class="btn sm pri" type="button" :disabled="!!busy || !dirty(group)" @click="save(group)">保存</button>
      </div>
      <div class="tblwrap">
        <table>
          <thead>
            <tr><th>启用</th><th>名称</th><th>协议</th><th>地址</th><th>拨号地址</th><th>走代理</th><th></th></tr>
          </thead>
          <tbody>
            <tr v-for="(upstream, index) in drafts[group.tag].upstreams" :key="`${upstream.tag}-${index}`">
              <td>
                <button class="sw" type="button" :class="{ on: upstream.enabled !== false }" :aria-pressed="upstream.enabled !== false" :aria-label="`启用：${upstream.tag}`" @click="upstream.enabled = upstream.enabled === false"></button>
              </td>
              <td class="mono">{{ upstream.tag }}</td>
              <td>{{ protocolName(upstream) }}</td>
              <td class="mono">{{ upstream.addr }}</td>
              <td class="mono t2">{{ upstream.dial_addr || '—' }}</td>
              <td>
                <button class="sw" type="button" :class="{ on: !!upstream.use_proxy }" :disabled="noProxy(upstream)" :aria-pressed="!!upstream.use_proxy" :aria-label="`走代理：${upstream.tag}`" @click="upstream.use_proxy = !upstream.use_proxy"></button>
              </td>
              <td><button class="btn sm" type="button" @click="editing = { group, index }">编辑</button></td>
            </tr>
          </tbody>
        </table>
      </div>
      <button class="btn sm ghost" type="button" style="margin-top: 8px" @click="editing = { group, index: -1 }">＋ 添加上游</button>
    </fieldset>
  </div>

  <UpstreamModal
    v-if="editing"
    :group="editing.group ? drafts[editing.group.tag].name : ''"
    :upstream="editing.group && editing.index >= 0 ? drafts[editing.group.tag].upstreams[editing.index] : undefined"
    :tags="allTags"
    :with-name="!editing.group"
    :pending="busy === 'new'"
    @close="editing = null"
    @save="saveUpstream"
    @remove="removeUpstream"
  />
  <AppModal v-if="confirming" :title="confirming.kind === 'restore' ? `恢复「${confirming.group.name}」的默认上游` : `删除上游组「${confirming.group.name}」`" @close="confirming = null">
    <template #footer>
      <button class="btn" type="button" @click="confirming = null">取消</button>
      <button class="btn red" type="button" :disabled="!!busy" @click="confirmed">{{ confirming.kind === 'restore' ? '恢复默认' : '删除' }}</button>
    </template>
  </AppModal>
</template>
