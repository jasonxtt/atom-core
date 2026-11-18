<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ApiError, call, client, describe } from '../api/client'
import AppModal from './AppModal.vue'
import { groupTypeLabels, loadProviders, poolNodes, providers } from '../composables/proxy'
import { toast } from '../composables/toast'

const props = defineProps<{ target: 'sing-box' | 'mihomo' }>()
const emit = defineEmits<{ close: []; done: [] }>()

interface Brief {
  id: string
  name: string
  type?: string
  reason?: string
}
interface Check {
  provider_count: number
  inactive_nodes: Brief[]
  blocked_providers: Brief[]
  groups_to_handle: Brief[]
  provider_only_groups: Brief[]
}
const check = ref<Check | null>(null)
const error = ref('')
const busy = ref(false)
// What to do with each fallback / load-balance group when switching to sing-box.
const actions = reactive<Record<string, 'urltest' | 'delete'>>({})

async function load() {
  error.value = ''
  try {
    const answer = (await call(client.GET('/settings/backend-check', { params: { query: { target: props.target } } }))) as unknown as Check
    for (const group of answer.groups_to_handle ?? []) actions[group.id] ??= 'urltest'
    for (const id of Object.keys(actions)) if (!answer.groups_to_handle?.some((group) => group.id === id)) delete actions[id]
    if (props.target === 'sing-box' && answer.provider_count) await loadProviders().catch(() => {})
    check.value = answer
  } catch (failure) {
    check.value = null
    error.value = describe(failure)
  }
}
onMounted(load)

const inactive = computed(() => check.value?.inactive_nodes ?? [])
const blocked = computed(() => check.value?.blocked_providers ?? [])
const handle = computed(() => check.value?.groups_to_handle ?? [])
const providerOnly = computed(() => check.value?.provider_only_groups ?? [])
const countOf = (id: string) => poolNodes.value.filter((node) => node.provider_id === id).length

async function confirm() {
  busy.value = true
  error.value = ''
  try {
    const body = props.target === 'sing-box' ? { backend: props.target, group_actions: { ...actions } } : { backend: props.target, ...(inactive.value.length ? { confirm_inactive_nodes: true } : {}) }
    await call(client.PUT('/settings', { body }))
    toast('ok', `已切换到 ${props.target}`)
    emit('done')
  } catch (failure) {
    if (failure instanceof ApiError && (failure.status === 409 || failure.status === 400)) {
      await load()
      error.value = check.value ? '内容在打开窗口后变了，已刷新，请重新确认' : `${error.value}（${failure.status}）`
    } else {
      error.value = describe(failure)
    }
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <AppModal :title="`切换到 ${target}`" @close="emit('close')">
    <template v-if="check">
      <template v-if="target === 'sing-box'">
        <div v-if="check.provider_count" class="grid" style="gap: 8px">
          <h4 class="sec">订阅 <span class="tag">{{ check.provider_count }}</span></h4>
          <div class="warnbox">订阅节点在 sing-box 下不可用。订阅保留，切回 mihomo 时恢复。</div>
          <div v-for="provider in providers" :key="provider.id" class="item">
            <span class="nm">{{ provider.name }}</span>
            <span class="t2">{{ countOf(provider.id) }} 个节点</span>
          </div>
        </div>
        <div v-if="handle.length" class="grid" style="gap: 8px">
          <h4 class="sec">sing-box 不支持的组 <span class="tag">{{ handle.length }}</span></h4>
          <div v-for="group in handle" :key="group.id" class="item">
            <span class="nm">{{ group.name }} <span class="tag">{{ groupTypeLabels[group.type as keyof typeof groupTypeLabels] ?? group.type ?? '' }}</span></span>
            <div class="seg sm" role="radiogroup" :aria-label="`${group.name}的处理`">
              <button type="button" role="radio" :aria-checked="actions[group.id] === 'urltest'" :class="{ on: actions[group.id] === 'urltest' }" @click="actions[group.id] = 'urltest'">转换为自动测速</button>
              <button type="button" role="radio" :aria-checked="actions[group.id] === 'delete'" :class="{ on: actions[group.id] === 'delete' }" :style="actions[group.id] === 'delete' ? { color: 'var(--bad)' } : undefined" @click="actions[group.id] = 'delete'">删除</button>
            </div>
          </div>
          <div class="t2">删除的组被规则引用时，这些规则改为走 Final。</div>
        </div>
        <div v-if="providerOnly.length" class="grid" style="gap: 8px">
          <h4 class="sec">切换后没有可用成员的组 <span class="tag">{{ providerOnly.length }}</span></h4>
          <div v-for="group in providerOnly" :key="group.id" class="item">
            <span class="nm">{{ group.name }}</span>
            <span class="pill bad">拒绝流量</span>
          </div>
        </div>
      </template>
      <div v-else-if="inactive.length" class="grid" style="gap: 8px">
        <h4 class="sec">mihomo 不支持的节点 <span class="tag">{{ inactive.length }}</span></h4>
        <div class="warnbox">这些节点在 mihomo 下不生效，会从所在的组里暂时移除。节点保留，切回 sing-box 时恢复。</div>
        <div v-for="node in inactive" :key="node.id" class="item">
          <span class="nm">{{ node.name }} <span class="tag">{{ (node.type ?? '').toUpperCase() }}</span></span>
          <span class="t2">{{ node.reason }}</span>
        </div>
      </div>
      <div v-if="blocked.length" class="err">
        这些订阅经由不生效的节点下载，切换会失败：{{ blocked.map((item) => item.name).join('、') }}。请先改它们的下载方式。
      </div>
      <div class="t2">切换期间代理会短暂中断，已有连接会断开。</div>
    </template>
    <div v-else-if="!error" class="t2">读取中…</div>
    <div v-if="error" class="err">{{ error }}</div>
    <template #footer>
      <button class="btn" type="button" @click="emit('close')">取消</button>
      <button v-if="!check && error" class="btn" type="button" @click="load">重试</button>
      <button class="btn pri" type="button" :disabled="busy || !check || blocked.length > 0" @click="confirm">确认切换</button>
    </template>
  </AppModal>
</template>
