<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ApiError, call, client, describe, type Schemas } from '../api/client'
import { backendName, backendStartedAt, backendVersion, refreshStatus, status } from '../composables/status'
import { toast } from '../composables/toast'
import { ago, duration, triggers } from '../format'
import SettingsTabs from '../components/SettingsTabs.vue'
import SwitchBackendModal from '../components/SwitchBackendModal.vue'
import { loadProxy } from '../composables/proxy'

const settings = ref<Schemas['Settings'] | null>(null)
const form = reactive({ fakeip_range: '', resolver: '', mixed_port: '' })
const error = ref('')
const saving = ref(false)

function fill(value: Schemas['Settings']) {
  settings.value = value
  form.fakeip_range = value.fakeip_range
  form.resolver = value.resolver
  form.mixed_port = String(value.mixed_port)
}

/** Whether the settings were read (a failure is shown in the form). */
async function load(): Promise<boolean> {
  try {
    fill(await call(client.GET('/settings')))
    return true
  } catch (failure) {
    error.value = describe(failure)
    return false
  }
}
onMounted(load)

const changed = computed(() => {
  const current = settings.value
  if (!current) return false
  return form.fakeip_range.trim() !== current.fakeip_range || form.resolver.trim() !== current.resolver || form.mixed_port.trim() !== String(current.mixed_port)
})

async function save() {
  const current = settings.value
  if (!current) return
  const port = Number(form.mixed_port.trim())
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    error.value = 'mixed 端口应为 1–65535 的整数'
    return
  }
  // Only what changed is sent, with the version it was read at.
  const body: { version: number; fakeip_range?: string; resolver?: string; mixed_port?: number } = { version: current.version }
  if (form.fakeip_range.trim() !== current.fakeip_range) body.fakeip_range = form.fakeip_range.trim()
  if (form.resolver.trim() !== current.resolver) body.resolver = form.resolver.trim()
  if (port !== current.mixed_port) body.mixed_port = port
  saving.value = true
  error.value = ''
  try {
    fill(await call(client.PUT('/settings', { body })))
    toast('ok', '已保存')
  } catch (failure) {
    if (failure instanceof ApiError && failure.status === 409 && failure.body?.version !== undefined) {
      if (await load()) toast('warn', '设置已在别处修改，已载入最新内容（409）')
      else error.value = `设置已在别处修改（409），重新读取失败：${error.value}`
    } else {
      error.value = describe(failure)
    }
  } finally {
    saving.value = false
    refreshStatus().catch(() => {})
  }
}

const switching = ref<'sing-box' | 'mihomo' | null>(null)
async function switched() {
  switching.value = null
  // the settings are read again (the kernel changed); unsaved edits of the form stay
  const old = settings.value
  const draft = { ...form }
  await Promise.all([load(), loadProxy().catch(() => {}), refreshStatus().catch(() => {})])
  if (old) {
    if (draft.fakeip_range !== old.fakeip_range) form.fakeip_range = draft.fakeip_range
    if (draft.resolver !== old.resolver) form.resolver = draft.resolver
    if (draft.mixed_port !== String(old.mixed_port)) form.mixed_port = draft.mixed_port
  }
}

const applying = ref(false)
async function reapply() {
  applying.value = true
  try {
    await call(client.POST('/apply'))
    toast('ok', `已重新应用到 ${backendName.value}`)
  } catch (failure) {
    toast('bad', describe(failure))
  } finally {
    applying.value = false
    refreshStatus().catch(() => {})
  }
}
</script>

<template>
  <SettingsTabs />
  <section class="card grid" style="gap: 14px">
    <div class="hd" style="margin: 0">
      <h2>代理内核</h2>
      <span class="sp"></span>
      <div class="seg" role="group" aria-label="切换代理内核">
        <button v-for="name in ['sing-box', 'mihomo']" :key="name" type="button" :class="{ on: backendName === name }" :aria-pressed="backendName === name" @click="backendName !== name && (switching = name as 'sing-box' | 'mihomo')">{{ name }}</button>
      </div>
    </div>
    <div class="grid g3" style="gap: 10px">
      <div class="tile">
        <div class="k">当前内核</div>
        <div class="v">{{ status ? backendName : '—' }}</div>
        <div class="s mono">{{ backendVersion || '—' }}</div>
      </div>
      <div class="tile">
        <div class="k">状态</div>
        <div class="v" :style="status && !status.singbox.running ? { color: 'var(--bad)' } : undefined">
          {{ !status ? '—' : status.singbox.running ? '运行中' : '未运行' }}
        </div>
        <div v-if="status?.singbox.running && backendStartedAt" class="s">已运行 {{ duration(Math.max(0, Date.now() / 1000 - backendStartedAt)) }}</div>
      </div>
      <div class="tile">
        <div class="k">配置</div>
        <template v-if="status && !status.singbox.in_sync">
          <div class="row" style="gap: 8px">
            <span class="v" style="color: var(--warn)">未同步</span>
            <button class="btn sm" type="button" :disabled="applying" @click="reapply">重新应用</button>
          </div>
          <div v-if="status.last_apply && !status.last_apply.ok" class="s">上次应用失败 · {{ ago(status.last_apply.at) }}</div>
        </template>
        <template v-else>
          <div class="v">{{ status ? '已同步' : '—' }}</div>
          <div v-if="status?.last_apply" class="s">最近应用 · {{ ago(status.last_apply.at) }} · {{ triggers[status.last_apply.trigger] ?? status.last_apply.trigger }}</div>
        </template>
      </div>
    </div>
  </section>

  <form class="card grid" style="gap: 12px" @submit.prevent="save">
    <div class="hd" style="margin: 0">
      <h2>通用</h2>
      <span class="sp"></span>
      <button class="btn sm pri" type="submit" :disabled="!changed || saving">保存</button>
    </div>
    <div class="grid g3" style="gap: 12px">
      <div class="field">
        <label for="fakeip">FakeIP 网段</label>
        <input id="fakeip" v-model="form.fakeip_range" class="inp mono" autocomplete="off" :disabled="saving || !settings" />
      </div>
      <div class="field">
        <label for="resolver">解析节点域名用的 DNS</label>
        <input
          id="resolver"
          v-model="form.resolver"
          class="inp mono"
          autocomplete="off"
          :disabled="saving || !settings"
          :placeholder="settings ? `留空：${settings.resolver_effective}` : ''"
        />
      </div>
      <div class="field">
        <label for="mixed">mixed 代理端口</label>
        <input id="mixed" v-model="form.mixed_port" class="inp mono" inputmode="numeric" autocomplete="off" :disabled="saving || !settings" />
      </div>
    </div>
    <div v-if="error" class="row">
      <div class="err" style="flex: 1">{{ error }}</div>
      <button v-if="!settings" class="btn" type="button" @click="load">重试</button>
    </div>
  </form>
  <SwitchBackendModal v-if="switching" :target="switching" @close="switching = null" @done="switched" />
</template>
