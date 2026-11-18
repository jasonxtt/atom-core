<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import { ApiError, call, client, describe } from '../api/client'
import AppModal from './AppModal.vue'
import { loadProviders, loadProxy, nodes, providers, version, type Provider } from '../composables/proxy'
import { refreshStatus } from '../composables/status'
import { toast } from '../composables/toast'

/** Add a subscription (no `provider`), or edit one. */
const props = defineProps<{ provider?: Provider }>()
const emit = defineEmits<{ close: [] }>()

const intervals: [number, string][] = [
  [3600, '1 小时'],
  [21600, '6 小时'],
  [43200, '12 小时'],
  [86400, '1 天']
]
const form = reactive({
  name: props.provider?.name ?? '',
  url: '',
  interval: props.provider?.interval ?? 3600,
  via: props.provider?.download_via ?? '',
  filter: props.provider?.filter ?? ''
})
const intervalOptions = computed(() => (intervals.some((item) => item[0] === form.interval) ? intervals : [...intervals, [form.interval, `${form.interval} 秒`] as [number, string]]))
const viaOptions = computed(() => nodes.value.filter((node) => node.active !== false))
const error = ref('')
const busy = ref(false)
// The version the dialog opened at; a change made elsewhere since is refused (409).
const formVersion = ref(version.value)

async function submit() {
  error.value = ''
  const name = form.name.trim()
  const url = form.url.trim()
  if (!name) {
    error.value = '请填写名称'
    return
  }
  if (!props.provider && !url) {
    error.value = '请填写订阅地址'
    return
  }
  if (form.filter.trim()) {
    try {
      new RegExp(form.filter.trim())
    } catch {
      error.value = '筛选正则无效'
      return
    }
  }
  const body = { name, ...(url ? { url } : {}), interval: form.interval, filter: form.filter.trim(), download_via: form.via || null, version: formVersion.value }
  busy.value = true
  try {
    if (props.provider) await call(client.PUT('/providers/{id}', { params: { path: { id: props.provider.id } }, body }))
    else await call(client.POST('/providers', { body: { ...body, url } as never }))
    toast('ok', '已保存')
    await loadProxy().catch(() => {})
    emit('close')
  } catch (failure) {
    if (failure instanceof ApiError && failure.status === 409 && failure.body?.version !== undefined) {
      try {
        await Promise.all([loadProxy(), loadProviders()])
        formVersion.value = version.value
        const latest = providers.value.find((item) => item.id === props.provider?.id)
        if (latest) Object.assign(form, { name: latest.name, interval: latest.interval, via: latest.download_via ?? '', filter: latest.filter })
        error.value = '节点或订阅已在别处修改，已载入最新内容，请检查后再保存（409）'
      } catch (reloadFailure) {
        error.value = `节点或订阅已在别处修改（409），重新读取失败：${describe(reloadFailure)}`
      }
    } else {
      error.value = describe(failure)
    }
  } finally {
    busy.value = false
    void loadProviders().catch(() => {})
    refreshStatus().catch(() => {})
  }
}
</script>

<template>
  <AppModal :title="provider ? '编辑订阅' : '添加订阅'" @close="emit('close')">
    <div class="field">
      <label for="pname">名称</label>
      <input id="pname" v-model="form.name" class="inp" autocomplete="off" />
    </div>
    <div class="field">
      <label for="purl">订阅地址</label>
      <input id="purl" v-model="form.url" class="inp mono" placeholder="https://" autocomplete="off" spellcheck="false" />
      <div v-if="provider" class="hint">留空保留原地址</div>
    </div>
    <div class="grid g2" style="gap: 12px">
      <div class="field">
        <label for="pint">更新间隔</label>
        <select id="pint" v-model.number="form.interval" class="inp">
          <option v-for="item in intervalOptions" :key="item[0]" :value="item[0]">{{ item[1] }}</option>
        </select>
      </div>
      <div class="field">
        <label for="pvia">下载方式</label>
        <select id="pvia" v-model="form.via" class="inp">
          <option value="">直连</option>
          <option v-for="node in viaOptions" :key="node.id" :value="node.id">经 {{ node.name }}</option>
        </select>
      </div>
    </div>
    <div class="field">
      <label for="pflt">筛选节点（正则，可选）</label>
      <input id="pflt" v-model="form.filter" class="inp mono" placeholder="例：香港|日本" autocomplete="off" spellcheck="false" />
    </div>
    <div v-if="error" class="err">{{ error }}</div>
    <template #footer>
      <button class="btn" type="button" @click="emit('close')">取消</button>
      <button class="btn pri" type="button" :disabled="busy" @click="submit">{{ provider ? '保存' : '添加' }}</button>
    </template>
  </AppModal>
</template>
