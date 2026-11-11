<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import draggable from 'vuedraggable'
import { ApiError, call, client, describe, type Schemas } from '../api/client'
import AppModal from '../components/AppModal.vue'
import GroupCard from '../components/GroupCard.vue'
import { testGroup } from '../composables/delay'
import { usePoll } from '../composables/poll'
import { groupViews, loadProxy, loadRuntime, order, reportFailure, version, type GroupView } from '../composables/proxy'
import { refreshStatus } from '../composables/status'
import { toast } from '../composables/toast'

const router = useRouter()
const editing = ref(false)
const open = reactive<Record<string, boolean>>({})
const error = ref('')

async function load() {
  try {
    await loadProxy()
    error.value = ''
  } catch (failure) {
    error.value = describe(failure)
  }
}
onMounted(load)
usePoll(loadRuntime, 5000)

// Columns as zashboard: a fixed number by width, groups dealt round-robin, so opening a card
// only pushes the cards below it in its column.
const root = ref<HTMLElement | null>(null)
const columns = ref(2)
let observer: ResizeObserver | undefined
onMounted(() => {
  observer = new ResizeObserver(([entry]) => {
    columns.value = Math.max(1, Math.floor((entry.contentRect.width + 16) / (380 + 16)))
  })
  if (root.value) observer.observe(root.value)
})
onUnmounted(() => observer?.disconnect())
const dealt = computed(() => Array.from({ length: columns.value }, (_, column) => groupViews.value.filter((_, index) => index % columns.value === column)))

// Each group's download rate: the growth of the connections whose chain passes through it.
const traffic = ref<Record<string, number>>({})
let previous: { at: number; down: Map<string, number> } | null = null
usePoll(async () => {
  let snapshot
  try {
    snapshot = await call(client.GET('/connections'))
  } catch {
    traffic.value = {}
    previous = null
    return
  }
  const at = Date.now()
  const down = new Map<string, number>()
  const rates: Record<string, number> = {}
  for (const item of (snapshot.connections ?? []) as { id: string; download?: number; chains?: string[] }[]) {
    const bytes = item.download ?? 0
    down.set(item.id, bytes)
    const before = previous?.down.get(item.id)
    if (previous && before !== undefined && at > previous.at) {
      const speed = Math.max(0, bytes - before) / ((at - previous.at) / 1000)
      for (const tag of item.chains ?? []) rates[tag] = (rates[tag] ?? 0) + speed
    }
  }
  traffic.value = rates
  previous = { at, down }
}, 2000)

// Edit mode: a working copy of the order; a drop moves one card on the server.
const editList = ref<GroupView[]>([])
watch([editing, groupViews], () => {
  if (editing.value) editList.value = [...groupViews.value]
})
async function moved(event: { newIndex: number; oldIndex: number }) {
  if (event.newIndex === event.oldIndex) return
  const list = editList.value
  const id = list[event.newIndex].id
  const body: { id: string; version: number; before_id?: string; after_id?: string } = { id, version: version.value }
  if (event.newIndex + 1 < list.length) body.before_id = list[event.newIndex + 1].id
  else body.after_id = list[event.newIndex - 1].id
  try {
    const answer = await call(client.POST('/groups/move', { body }))
    order.value = answer.order
    version.value = answer.version
  } catch (failure) {
    await reportFailure(failure)
    editList.value = [...groupViews.value]
  }
}

const testingAll = ref(false)
async function testAll() {
  testingAll.value = true
  await Promise.all(groupViews.value.map((view) => testGroup(view.id)))
  testingAll.value = false
}

// Deleting: a group that rules proxy to needs a second confirmation (they move to Final).
const removing = ref<{ view: GroupView; rules: Schemas['Rule'][] | null } | null>(null)
const busy = ref(false)
async function remove(confirm: boolean) {
  const target = removing.value
  if (!target) return
  busy.value = true
  try {
    await call(
      client.DELETE('/groups/{id}', {
        params: { path: { id: target.view.id }, query: confirm ? { version: version.value, confirm: true } : { version: version.value } }
      })
    )
    toast('ok', `已删除「${target.view.name}」`)
    removing.value = null
    await load()
  } catch (failure) {
    const ids = failure instanceof ApiError && failure.status === 409 ? failure.body?.rules : undefined
    if (ids?.length && !confirm) {
      const table = await call(client.GET('/rules')).catch(() => null)
      target.rules = table ? table.rules.filter((rule) => ids.includes(rule.id)) : ids.map((id) => ({ id }) as Schemas['Rule'])
    } else {
      removing.value = null
      await reportFailure(failure)
    }
  } finally {
    busy.value = false
    refreshStatus().catch(() => {})
  }
}
const ruleLabel = (rule: Schemas['Rule']) => rule.remark || rule.id
</script>

<template>
  <Teleport to="#top-actions" defer>
    <button class="btn" :class="{ pri: editing }" type="button" @click="editing = !editing">{{ editing ? '完成' : '编辑' }}</button>
    <button v-if="!editing" class="btn" type="button" :disabled="testingAll" @click="testAll">全部测速</button>
    <button class="btn pri" type="button" @click="router.push('/groups/new')">＋ 添加节点组</button>
  </Teleport>

  <div ref="root">
    <div v-if="error" class="err">{{ error }}</div>
    <div v-if="!editing" class="gcols">
      <div v-for="(column, index) in dealt" :key="index" class="gcol">
        <GroupCard
          v-for="view in column"
          :key="view.id"
          :view="view"
          :open="open[view.id]"
          :traffic="traffic[view.id] ?? 0"
          @toggle="open[view.id] = !open[view.id]"
        />
      </div>
    </div>
    <draggable
      v-else
      v-model="editList"
      item-key="id"
      class="gcards editing"
      :style="{ gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))` }"
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
      @end="moved"
    >
      <template #item="{ element }">
        <GroupCard
          :view="element"
          editing
          :traffic="traffic[element.id] ?? 0"
          @edit="router.push(`/groups/${element.id}`)"
          @remove="removing = { view: element, rules: null }"
        />
      </template>
    </draggable>
  </div>

  <AppModal v-if="removing" :title="`删除节点组「${removing.view.name}」`" @close="removing = null">
    <template v-if="removing.rules">
      <div class="err">有 {{ removing.rules.length }} 条规则代理到这个组，删除后这些规则改为代理到兜底分组：</div>
      <div class="tile" style="font-size: 12.5px">
        <div v-for="rule in removing.rules" :key="rule.id">{{ ruleLabel(rule) }}</div>
      </div>
    </template>
    <template #footer>
      <button class="btn" type="button" @click="removing = null">取消</button>
      <button class="btn red" type="button" :disabled="busy" @click="remove(!!removing.rules)">{{ removing.rules ? '仍然删除' : '删除' }}</button>
    </template>
  </AppModal>
</template>
