<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ApiError, call, client, describe, type Schemas } from '../api/client'
import { refreshStatus, singboxVersion, status } from '../composables/status'
import { setTheme, theme, themeLabels, type Theme } from '../composables/theme'
import { toast } from '../composables/toast'
import { ago, triggers } from '../format'

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

const applying = ref(false)
async function reapply() {
  applying.value = true
  try {
    await call(client.POST('/apply'))
    toast('ok', '已重新应用到 sing-box')
  } catch (failure) {
    toast('bad', describe(failure))
  } finally {
    applying.value = false
    refreshStatus().catch(() => {})
  }
}

const themes: Theme[] = ['system', 'light', 'dark']
const uiVersion = __UI_VERSION__
</script>

<template>
  <div class="grid g2" style="align-items: start">
    <form class="card grid" style="gap: 12px" @submit.prevent="save">
      <div class="hd" style="margin: 0">
        <h2>代理（sing-box）</h2>
        <span class="sp"></span>
        <button class="btn sm pri" type="submit" :disabled="!changed || saving">保存</button>
      </div>
      <div class="field">
        <label for="fakeip">FakeIP 网段</label>
        <input id="fakeip" v-model="form.fakeip_range" class="inp mono" autocomplete="off" />
      </div>
      <div class="field">
        <label for="resolver">解析节点域名用的 DNS</label>
        <input
          id="resolver"
          v-model="form.resolver"
          class="inp mono"
          autocomplete="off"
          :placeholder="settings ? `留空：${settings.resolver_effective}` : ''"
        />
      </div>
      <div class="field">
        <label for="mixed">mixed 代理端口</label>
        <input id="mixed" v-model="form.mixed_port" class="inp mono" inputmode="numeric" autocomplete="off" />
      </div>
      <div v-if="error" class="err">{{ error }}</div>
    </form>

    <div class="grid" style="gap: 16px">
      <div class="card grid" style="gap: 10px">
        <h2>应用</h2>
        <div class="row" v-if="status">
          <span class="pill" :class="status.singbox.in_sync ? 'ok' : 'warn'"><span class="dot"></span>{{ status.singbox.in_sync ? '配置已同步' : '配置未同步' }}</span>
          <span class="t2" v-if="status.last_apply">
            最近：{{ ago(status.last_apply.at) }} · {{ triggers[status.last_apply.trigger] ?? status.last_apply.trigger }} ·
            {{ status.last_apply.ok ? '成功' : '失败' }}
          </span>
        </div>
        <div><button class="btn" :disabled="applying" @click="reapply">重新应用到 sing-box</button></div>
      </div>
      <div class="card grid" style="gap: 10px">
        <h2>外观</h2>
        <div class="seg" style="justify-self: start">
          <button v-for="item in themes" :key="item" type="button" :class="{ on: theme === item }" @click="setTheme(item)">{{ themeLabels[item] }}</button>
        </div>
      </div>
      <div class="card grid" style="gap: 10px">
        <h2>关于</h2>
        <div class="grid g3" style="gap: 8px">
          <div class="tile"><div class="k">atomdns</div><div class="v mono">{{ status?.atomdns.version ?? '—' }}</div></div>
          <div class="tile"><div class="k">sing-box</div><div class="v mono">{{ singboxVersion || '—' }}</div></div>
          <div class="tile"><div class="k">WebUI</div><div class="v mono">{{ uiVersion }}</div></div>
        </div>
      </div>
    </div>
  </div>
</template>
