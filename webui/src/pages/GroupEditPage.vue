<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import draggable from 'vuedraggable'
import { ApiError, call, client, describe } from '../api/client'
import { FINAL, FINAL_NAME, groups, isGroup, loadProxy, membersOf, nameOf, nodes, final, version } from '../composables/proxy'
import { refreshStatus } from '../composables/status'
import { toast } from '../composables/toast'

const route = useRoute()
const router = useRouter()
// `/groups/new` has no `id` parameter.
const id = computed(() => (typeof route.params.id === 'string' ? route.params.id : ''))
const isFinal = computed(() => id.value === FINAL)

const form = reactive({
  name: '',
  type: 'selector' as 'selector' | 'urltest',
  members: [] as string[],
  filter: '',
  order: [] as string[],
  selected: '',
  url: '',
  interval: '',
  tolerance: '',
  builtin: false
})
const loaded = ref(false)
const error = ref('')
const saving = ref(false)
// The version the form was filled from; a save carries it, so a change made elsewhere since
// is refused (409) instead of being overwritten.
const formVersion = ref(0)
// After a 409: what is saved now, for the user to compare with the form.
// Every field a save replaces is shown.
type Saved = { name: string; type: string; members: string[]; filter?: string; selected?: string; url?: string; interval?: string; tolerance?: number }
const conflict = ref<Saved | null>(null)

function latest(): Saved | null {
  if (isFinal.value) return final.value ? { name: FINAL_NAME, type: 'selector', members: final.value.members, selected: final.value.selected } : null
  const group = groups.value.find((item) => item.id === id.value)
  return group
    ? { name: group.name, type: group.type, members: group.members, filter: group.filter, selected: group.selected, url: group.url, interval: group.interval, tolerance: group.tolerance }
    : null
}

function fill() {
  formVersion.value = version.value
  conflict.value = null
  if (isFinal.value) {
    Object.assign(form, { name: FINAL_NAME, type: 'selector', members: [...(final.value?.members ?? [])], selected: final.value?.selected ?? '', builtin: true })
    return
  }
  const group = groups.value.find((item) => item.id === id.value)
  if (!group) return
  Object.assign(form, {
    name: group.name,
    type: group.type,
    members: [...group.members],
    filter: group.filter ?? '',
    order: [...(group.order ?? [])],
    selected: group.selected ?? '',
    url: group.url ?? '',
    interval: group.interval ?? '',
    tolerance: group.tolerance === undefined ? '' : String(group.tolerance),
    builtin: group.builtin
  })
}

// A save replaces the whole group: the form opens only once the state was read and the group
// edited exists; else the error and a retry.
async function load() {
  loaded.value = false
  error.value = ''
  try {
    await loadProxy()
  } catch (failure) {
    error.value = `读取失败：${describe(failure)}`
    return
  }
  if (id.value && !isFinal.value && !groups.value.some((item) => item.id === id.value)) {
    error.value = '节点组不存在'
    return
  }
  fill()
  loaded.value = true
}
onMounted(load)

// Candidates: nodes and the other groups (Final is never a member; Final itself takes groups).
const filter = ref<'all' | 'node' | 'group'>('all')
// The name filter (a regular expression, case-insensitive; a plain keyword is one): the nodes
// it matches are members that cannot be unticked one by one. The server decides at save time
// (Rust's regex); this is the preview.
const filterText = computed(() => form.filter.trim())
const filterRegex = computed(() => {
  if (!filterText.value) return null
  try {
    return new RegExp(filterText.value, 'i')
  } catch {
    return false as const
  }
})
const locked = computed(() => {
  const regex = filterRegex.value
  return new Set(regex ? nodes.value.filter((node) => regex.test(node.name)).map((node) => node.id) : [])
})
// Everything the group will hold: the ticked members, then the filtered nodes not among them.
// The selected members as the right list shows them, in the order the group will have: the
// stored `order` first, then what it does not name (the ticked members, then the filtered nodes).
const shown = computed({
  get() {
    const base = [...form.members, ...[...locked.value].filter((member) => !form.members.includes(member))]
    const ordered = form.order.filter((member, at) => base.includes(member) && form.order.indexOf(member) === at)
    return [...ordered, ...base.filter((member) => !ordered.includes(member))]
  },
  set(list: string[]) {
    form.order = list
    form.members = list.filter((member) => form.members.includes(member))
  }
})
const memberCount = computed(() => shown.value.length)

const candidates = computed(() => {
  const groupItems =
    filter.value === 'node'
      ? []
      : groups.value
          .filter((group) => group.id !== id.value)
          .map((group) => ({ id: group.id, name: group.name, group: true, sub: `${group.type === 'selector' ? '手动' : '自动测速'} · ${membersOf(group).length} 个成员` }))
  const nodeItems =
    filter.value === 'group'
      ? []
      : nodes.value.map((node) => ({ id: node.id, name: node.name, group: false, sub: `${node.type ?? ''} · ${node.server ?? ''}:${node.server_port ?? ''}` }))
  return [...groupItems, ...nodeItems]
})

const isPicked = (member: string) => form.members.includes(member) || locked.value.has(member)
const pickedCount = computed(() => candidates.value.filter((item) => isPicked(item.id)).length)
const allPicked = computed(() => candidates.value.length > 0 && pickedCount.value === candidates.value.length)

/** Ticks every candidate in the current list (the filter tabs apply); ticking again clears them. */
function toggleAll() {
  const ids = candidates.value.map((item) => item.id).filter((member) => !locked.value.has(member))
  if (allPicked.value) form.members = form.members.filter((member) => !ids.includes(member))
  else form.members.push(...ids.filter((member) => !form.members.includes(member)))
}

function toggle(member: string) {
  if (locked.value.has(member)) return
  const index = form.members.indexOf(member)
  if (index < 0) form.members.push(member)
  else form.members.splice(index, 1)
}

/** Drops the form's edits and starts again from what is saved now. */
function reload() {
  error.value = ''
  fill()
}

async function save(overwrite = false) {
  error.value = ''
  if (overwrite) {
    formVersion.value = version.value
    conflict.value = null
  }
  const name = form.name.trim()
  if (!isFinal.value && !name) {
    error.value = '请填写名称'
    return
  }
  const tolerance = form.tolerance.trim()
  if (form.type === 'urltest' && tolerance && !/^\d+$/.test(tolerance)) {
    error.value = '容差应为毫秒数'
    return
  }
  // A selector keeps its choice while it is still a member ("" is the first member).
  const selected = isPicked(form.selected) ? form.selected : ''
  if (!isFinal.value && filterRegex.value === false) {
    error.value = '筛选正则无效'
    return
  }
  saving.value = true
  try {
    if (isFinal.value) {
      await call(client.PUT('/final', { body: { members: form.members, selected, version: formVersion.value } }))
    } else {
      const body = {
        name,
        type: form.type,
        members: form.members,
        filter: filterText.value,
        order: filterText.value ? shown.value : [],
        version: formVersion.value,
        ...(form.type === 'selector'
          ? { selected }
          : {
              ...(form.url.trim() ? { url: form.url.trim() } : {}),
              ...(form.interval.trim() ? { interval: form.interval.trim() } : {}),
              ...(tolerance ? { tolerance: Number(tolerance) } : {})
            })
      }
      if (id.value) await call(client.PUT('/groups/{id}', { params: { path: { id: id.value } }, body }))
      else await call(client.POST('/groups', { body }))
    }
    toast('ok', '已保存')
    await router.push('/groups')
  } catch (failure) {
    if (failure instanceof ApiError && failure.status === 409 && failure.body?.version !== undefined) {
      await loadProxy().catch(() => {})
      if (!id.value) {
        // A new group overwrites nothing: the next save carries the current version.
        formVersion.value = version.value
        error.value = '节点或节点组已在别处修改，已载入最新版本，请再保存一次（409）'
      } else {
        conflict.value = latest()
        if (!conflict.value) error.value = '这个节点组已在别处删除（409）'
      }
    } else {
      error.value = describe(failure)
    }
  } finally {
    saving.value = false
    refreshStatus().catch(() => {})
  }
}
</script>

<template>
  <div v-if="loaded" class="split4">
    <div class="grid" style="gap: 16px">
      <div class="card grid" style="gap: 14px">
        <h2>基本信息</h2>
        <div class="field">
          <label for="gname">名称</label>
          <input id="gname" v-model="form.name" class="inp" autocomplete="off" :disabled="isFinal" />
        </div>
        <div class="field">
          <span class="label">组模式</span>
          <div class="seg" style="align-self: flex-start">
            <button type="button" :class="{ on: form.type === 'selector' }" @click="form.type = 'selector'">手动</button>
            <button type="button" :class="{ on: form.type === 'urltest' }" :disabled="form.builtin" @click="form.type = 'urltest'">自动测速</button>
          </div>
        </div>
        <div v-if="form.type === 'urltest'" class="grid g3" style="gap: 10px">
          <div class="field">
            <label for="gurl">测速 URL</label>
            <input id="gurl" v-model="form.url" class="inp mono" placeholder="https://www.gstatic.com/generate_204" autocomplete="off" />
          </div>
          <div class="field">
            <label for="gint">间隔</label>
            <input id="gint" v-model="form.interval" class="inp mono" placeholder="3m" autocomplete="off" />
          </div>
          <div class="field">
            <label for="gtol">容差（ms）</label>
            <input id="gtol" v-model="form.tolerance" class="inp mono" placeholder="50" inputmode="numeric" autocomplete="off" />
          </div>
        </div>
      </div>
      <div class="card grid" style="gap: 12px">
        <div class="row">
          <h2>成员</h2>
          <span class="sp"></span>
          <div class="seg sm">
            <button v-for="item in [['all', '全部'], ['node', '节点'], ['group', '节点组']] as const" :key="item[0]" type="button" :class="{ on: filter === item[0] }" @click="filter = item[0]">
              {{ item[1] }}
            </button>
          </div>
          <div class="seg sm">
            <button type="button" :class="{ on: allPicked }" :disabled="!candidates.length" :title="`${pickedCount} / ${candidates.length}`" @click="toggleAll">全选</button>
          </div>
          <input v-if="!isFinal" v-model="form.filter" class="inp sm mono" style="width: 180px; font-size: 12.5px" placeholder="关键字筛选节点" aria-label="关键字筛选节点" autocomplete="off" spellcheck="false" />
          <span v-if="filterRegex === false" class="err">正则无效</span>
        </div>
        <div class="mgrid">
          <label v-for="item in candidates" :key="item.id" class="check" :class="{ on: isPicked(item.id) }">
            <input type="checkbox" :aria-label="item.name" :checked="isPicked(item.id)" :disabled="locked.has(item.id)" @change="toggle(item.id)" />
            <div>
              <div class="t1">{{ item.name }} <span v-if="item.group" class="tag">组</span> <span v-if="locked.has(item.id)" class="tag">筛选</span></div>
              <div class="t2 t1">{{ item.sub }}</div>
            </div>
          </label>
        </div>
      </div>
    </div>
    <div class="card grid sticky" style="gap: 10px">
      <div class="row">
        <h2>已选成员</h2>
        <span class="tag">{{ memberCount }}</span>
      </div>
      <draggable
        v-model="shown"
        :item-key="(member: string) => member"
        class="grid"
        style="gap: 6px"
        :animation="180"
        :force-fallback="true"
        :fallback-on-body="true"
        :fallback-tolerance="4"
        :delay="120"
        :delay-on-touch-only="true"
        filter="button"
        :prevent-on-filter="false"
        ghost-class="s-ghost"
        chosen-class="s-chosen"
        fallback-class="s-fallback"
      >
        <template #item="{ element }">
          <div class="srow">
            <span class="handle" aria-hidden="true">⠿</span>
            <span class="nm">{{ nameOf(element) }}</span>
            <span v-if="isGroup(element)" class="tag">组</span>
            <span v-if="locked.has(element)" class="tag">筛选</span>
            <button v-else class="ico" type="button" style="width: 24px; height: 24px" aria-label="移除" @click="form.members = form.members.filter((member) => member !== element)">✕</button>
          </div>
        </template>
      </draggable>
      <div v-if="!memberCount" class="err">空组</div>
      <div v-if="conflict" class="grid" style="gap: 8px">
        <div class="err">已在别处修改（409）。现在保存的是：</div>
        <div class="tile" style="font-size: 12.5px">
          <div>{{ conflict.name }} · {{ conflict.type === 'selector' ? '手动' : '自动测速' }}</div>
          <div class="t2">成员：{{ conflict.members.map(nameOf).join('、') || '空组' }}</div>
          <div v-if="conflict.filter" class="t2 mono">名称筛选：{{ conflict.filter }}</div>
          <div v-if="conflict.type === 'selector'" class="t2">选中：{{ conflict.selected ? nameOf(conflict.selected) : '第一个成员' }}</div>
          <template v-else>
            <div class="t2 mono">测速 URL：{{ conflict.url || '—' }}</div>
            <div class="t2 mono">间隔：{{ conflict.interval || '—' }} · 容差：{{ conflict.tolerance ?? '—' }}</div>
          </template>
        </div>
        <div class="row" style="justify-content: flex-end">
          <button class="btn" type="button" @click="reload">载入最新内容</button>
          <button class="btn red" type="button" :disabled="saving" @click="save(true)">仍然保存</button>
        </div>
      </div>
      <div v-if="error" class="err">{{ error }}</div>
      <div v-if="!conflict" class="row" style="justify-content: flex-end">
        <button class="btn" type="button" @click="router.push('/groups')">取消</button>
        <button class="btn pri" type="button" :disabled="saving || (!isFinal && !form.name.trim())" @click="save()">保存</button>
      </div>
    </div>
  </div>
  <div v-else-if="error" class="row">
    <div class="err" style="flex: 1">{{ error }}</div>
    <button class="btn" type="button" @click="load">重试</button>
  </div>
</template>
