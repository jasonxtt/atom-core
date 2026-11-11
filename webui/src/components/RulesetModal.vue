<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ApiError, call, client, describe } from '../api/client'
import AppModal from './AppModal.vue'
import { lines, loadRulesets, parseNames, type Builtin, type Ruleset } from '../composables/rules'
import { refreshStatus } from '../composables/status'
import { toast } from '../composables/toast'

/** A new custom ruleset, an edit of one, or a builtin set's download address. */
const props = defineProps<{ mode: 'new' | 'edit' | 'url'; target?: Ruleset | Builtin }>()
const emit = defineEmits<{ close: [] }>()

const FORMATS = ['auto', 'text', 'yaml', 'json', 'srs', 'mrs', 'dat']
const custom = props.target && props.target.type !== 'builtin' ? (props.target as Ruleset) : undefined
const form = reactive({
  type: (custom?.type === 'local' ? 'local' : 'remote') as 'remote' | 'local',
  name: props.target?.name ?? '',
  url: props.target?.url ?? '',
  format: custom?.format || 'auto',
  category: custom?.category ?? '',
  text: ''
})
const error = ref('')
const busy = ref(false)
const loading = ref(false)

// A local list is read for editing.
onMounted(async () => {
  if (props.mode !== 'edit' || custom?.type !== 'local') return
  loading.value = true
  try {
    const set = (await call(client.GET('/rulesets/{id}', { params: { path: { id: custom.id } } }))) as { rules?: string[] }
    form.text = (set.rules ?? []).join('\n')
  } catch (failure) {
    error.value = describe(failure)
  } finally {
    loading.value = false
  }
})

const stats = () => {
  const parsed = parseNames(form.text)
  return parsed.bad.length ? `无法识别：${parsed.bad.slice(0, 3).join('、')}` : `${parsed.count} 条`
}

async function submit() {
  error.value = ''
  busy.value = true
  try {
    if (props.mode === 'url' && props.target) {
      await call(client.PUT('/rulesets/{id}', { params: { path: { id: props.target.id } }, body: { url: form.url.trim() } }))
      toast('ok', '已保存并下载')
    } else {
      if (form.type === 'local' && parseNames(form.text).bad.length) throw new Error(stats())
      const source =
        form.type === 'remote'
          ? { type: 'remote' as const, url: form.url.trim(), format: form.format, ...(form.format === 'dat' ? { category: form.category.trim() } : {}) }
          : { type: 'local' as const, rules: lines(form.text) }
      const body = { name: form.name.trim(), ...source }
      if (props.mode === 'new') await call(client.POST('/rulesets', { body }))
      else if (custom) await call(client.PUT('/rulesets/{id}', { params: { path: { id: custom.id } }, body }))
      toast('ok', '已保存')
    }
    emit('close')
  } catch (failure) {
    // 502: saved, but the download failed (the old list stays).
    if (failure instanceof ApiError && failure.status === 502) {
      toast('warn', `已保存，但下载失败：${failure.message}`)
      emit('close')
    } else {
      error.value = failure instanceof ApiError ? describe(failure) : failure instanceof Error ? failure.message : String(failure)
    }
  } finally {
    busy.value = false
    await loadRulesets().catch(() => {})
    refreshStatus().catch(() => {})
  }
}

const titles = { new: '新建规则集', edit: '编辑规则集', url: '编辑下载地址' }
</script>

<template>
  <AppModal :title="`${titles[mode]}${target ? ` · ${target.name}` : ''}`" @close="emit('close')">
    <div v-if="mode === 'new'" class="seg" style="align-self: flex-start">
      <button type="button" :class="{ on: form.type === 'remote' }" @click="form.type = 'remote'">远程订阅</button>
      <button type="button" :class="{ on: form.type === 'local' }" @click="form.type = 'local'">本地列表</button>
    </div>
    <div v-if="mode !== 'url'" class="field">
      <label for="rsname">名称</label>
      <input id="rsname" v-model="form.name" class="inp" autocomplete="off" />
    </div>
    <template v-if="mode === 'url' || form.type === 'remote'">
      <div class="field">
        <label for="rsurl">URL</label>
        <input id="rsurl" v-model="form.url" class="inp mono" placeholder="https://…" autocomplete="off" />
      </div>
      <div v-if="mode !== 'url'" class="row">
        <div class="field">
          <label for="rsfmt">格式</label>
          <select id="rsfmt" v-model="form.format" class="inp" style="width: auto">
            <option v-for="format in FORMATS" :key="format" :value="format">{{ format }}</option>
          </select>
        </div>
        <div v-if="form.format === 'dat'" class="field" style="flex: 1">
          <label for="rscat">分类</label>
          <input id="rscat" v-model="form.category" class="inp mono" placeholder="例如 cn" autocomplete="off" />
        </div>
      </div>
    </template>
    <div v-if="mode !== 'url' && form.type === 'local'" class="field">
      <label for="rstext">名单</label>
      <textarea id="rstext" v-model="form.text" class="inp" style="min-height: 160px" :disabled="loading" placeholder="domain:example.com&#10;full:www.example.com&#10;keyword:tracker&#10;regexp:^ads?\d*\."></textarea>
      <span class="hint" :style="{ color: parseNames(form.text).bad.length ? 'var(--bad)' : '' }">{{ stats() }}</span>
    </div>
    <div v-if="error" class="err">{{ error }}</div>
    <template #footer>
      <button class="btn" type="button" @click="emit('close')">取消</button>
      <button class="btn pri" type="button" :disabled="busy || loading || (form.type === 'remote' && !form.url.trim())" @click="submit">保存</button>
    </template>
  </AppModal>
</template>
