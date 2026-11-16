<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { call, client, describe, type Schemas } from '../api/client'
import { acceptMaintenanceJob, maintenance, maintenanceBusy, maintenanceError, refreshMaintenance } from '../composables/maintenance'

const job = computed(() => maintenance.value?.job)
const checking = ref(false)
const networkError = ref('')
const updateError = ref('')
const view = ref<Schemas['MaintenanceNetworkView'] | null>(null)
const form = ref<Schemas['MaintenanceNetwork'] | null>(null)
const latest = computed(() => job.value?.kind === 'check' && job.value.phase === 'success' ? job.value.version : undefined)
const phaseLabels: Record<Schemas['MaintenanceJob']['phase'], string> = {
  checking: '正在检查',
  downloading: '正在下载',
  validating: '正在校验',
  applying: '正在应用，服务可能短暂断开',
  awaiting_confirmation: '等待确认',
  restoring: '正在恢复',
  success: '已完成',
  failed: '操作失败',
  restored: '已恢复',
  recovery_failed: '恢复失败',
}
const latestNotes = computed(() => latest.value ? `https://github.com/jasonxtt/atom/releases/tag/v${latest.value}` : '')
const networkChanged = computed(() => view.value && form.value &&
  JSON.stringify(view.value.config) !== JSON.stringify(form.value))
const urlLabel = (url: string) => new URL(url).host
const newURLs = computed(() => job.value?.new_urls ?? [])
const networkJob = computed(() => job.value?.kind === 'network' ? job.value : undefined)
const updateJob = computed(() => job.value?.kind !== 'network' ? job.value : undefined)
const canConfirm = computed(() => !!(networkJob.value?.phase === 'awaiting_confirmation' &&
  (networkJob.value.same_access || newURLs.value.some((value) => new URL(value).origin === window.location.origin))))
const deadline = computed(() => networkJob.value?.deadline ?
  new Date(networkJob.value.deadline).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '')

async function loadNetwork() {
  try {
    const response = await call(client.GET('/maintenance/network'))
    view.value = response
    form.value = { ...response.config, lan: [...response.config.lan] }
    networkError.value = ''
  } catch (failure) {
    networkError.value = describe(failure)
  }
}
onMounted(loadNetwork)
watch(() => networkJob.value?.done, (done, wasDone) => {
  const phase = networkJob.value?.phase
  if (done && wasDone === false && (phase === 'success' || phase === 'restored')) void loadNetwork()
})

function setTopology() {
  if (!form.value) return
  form.value.accept_gateway = false
  if (form.value.topology === 'bypass') {
    form.value.lan = form.value.lan.slice(0, 1)
    form.value.wan = ''
  } else {
    form.value.reply_via = false
    form.value.router = ''
  }
}

async function update(kind: 'check' | 'upgrade') {
  const version = latest.value
  if (kind === 'upgrade' && !version) return
  updateError.value = ''
  checking.value = true
  try {
    const next = kind === 'check'
      ? await call(client.POST('/maintenance/check', { body: {} }))
      : await call(client.POST('/maintenance/upgrade', { body: { version: version! } }))
    acceptMaintenanceJob(next)
  } catch (failure) {
    updateError.value = describe(failure)
    void refreshMaintenance()
  } finally {
    checking.value = false
  }
}

const networkBusy = ref(false)
async function saveNetwork() {
  if (!view.value || !form.value || networkBusy.value) return
  networkError.value = ''
  networkBusy.value = true
  try {
    const next = await call(client.POST('/maintenance/network', { body: {
      ...form.value, lan: [...form.value.lan], revision: view.value.revision,
    } }))
    acceptMaintenanceJob(next)
  } catch (failure) {
    networkError.value = describe(failure)
    void refreshMaintenance()
  } finally {
    networkBusy.value = false
  }
}

async function confirmNetwork() {
  if (!networkJob.value || networkBusy.value) return
  networkError.value = ''
  networkBusy.value = true
  try {
    await call(client.POST('/maintenance/confirm', { body: { id: networkJob.value.id } }))
    await refreshMaintenance()
  } catch (failure) {
    networkError.value = describe(failure)
  } finally {
    networkBusy.value = false
  }
}
</script>

<template>
  <div class="card grid" style="gap: 12px">
    <div class="hd" style="margin: 0">
      <h2>系统更新</h2>
      <span class="sp"></span>
      <span v-if="maintenance" class="mono">Atom v{{ maintenance.version }}</span>
    </div>
    <div v-if="maintenance && !maintenance.online" class="t2">当前安装包未配置在线升级。</div>
    <div v-if="updateJob" aria-live="polite">
      <div v-if="latest">可升级至 Atom v{{ latest }}</div>
      <div v-else-if="updateJob.kind === 'check' && updateJob.phase === 'success'">未发现可升级版本</div>
      <div v-else>{{ phaseLabels[updateJob.phase] }}<span v-if="updateJob.version"> · Atom v{{ updateJob.version }}</span></div>
      <div v-if="updateJob.source" class="t2">来源：{{ updateJob.source }}</div>
      <div v-if="updateJob.error" class="err">{{ updateJob.error }}</div>
    </div>
    <div v-if="updateError" class="err">{{ updateError }}</div>
    <div v-else-if="maintenanceError" :class="maintenanceBusy ? 't2' : 'err'">
      {{ maintenanceBusy ? '正在重新连接面板…' : maintenanceError }}
    </div>
    <div v-if="maintenance?.online" class="row">
      <button type="button" class="btn" :disabled="checking || maintenanceBusy || networkBusy" @click="update('check')">检查更新</button>
      <a v-if="latestNotes" class="btn" :href="latestNotes" target="_blank" rel="noopener noreferrer">发布说明</a>
      <button v-if="latest" type="button" class="btn pri" :disabled="checking || maintenanceBusy || networkBusy" @click="update('upgrade')">升级 Atom</button>
    </div>
    <div v-else-if="!maintenance && maintenanceError"><button type="button" class="btn" @click="refreshMaintenance">重试</button></div>
  </div>

  <form class="card grid" style="gap: 12px" @submit.prevent="saveNetwork">
    <div class="hd" style="margin: 0">
      <h2>网络</h2>
      <span class="sp"></span>
      <button v-if="form" type="submit" class="btn pri sm" :disabled="!networkChanged || networkBusy || checking || maintenanceBusy">试用并保存</button>
    </div>
    <div v-if="networkJob" class="grid" style="gap: 7px" aria-live="polite">
      <div>{{ phaseLabels[networkJob.phase] }}</div>
      <div v-if="networkJob.error" class="err">{{ networkJob.error }}</div>
      <template v-if="!networkJob.done && networkJob.phase !== 'restoring' && newURLs.length">
        <div class="t2">请在新面板地址确认。自检完成后有 3 分钟，超时会自动恢复。</div>
        <div v-if="deadline" class="t2">确认截止时间 {{ deadline }}</div>
        <div class="row" style="flex-wrap: wrap">
          <a v-for="url in newURLs" :key="url" class="btn sm" :href="url" target="_blank" rel="noopener noreferrer">{{ urlLabel(url) }}</a>
          <button v-if="canConfirm" type="button" class="btn pri sm" :disabled="networkBusy" @click="confirmNetwork">确认并保留</button>
        </div>
        <div v-if="networkJob.old_urls?.length" class="t2">
          恢复后可返回 <a v-for="url in networkJob.old_urls" :key="url" :href="url" style="margin-right: 8px">{{ urlLabel(url) }}</a>
        </div>
      </template>
    </div>
    <div v-if="networkError" class="row">
      <div class="err">{{ networkError }}</div>
      <button v-if="!maintenanceBusy" type="button" class="btn sm" @click="loadNetwork">重新读取</button>
    </div>

    <fieldset v-if="form && view" :disabled="networkBusy || maintenanceBusy" class="network-fields grid">
      <div class="field">
        <label for="atom-topology">拓扑</label>
        <select id="atom-topology" v-model="form.topology" class="inp" @change="setTopology">
          <option value="bypass">单网卡旁路由</option>
          <option value="gateway">双网卡网关</option>
        </select>
      </div>

      <div v-if="form.topology === 'bypass'" class="field">
        <label for="atom-lan">LAN 网卡</label>
        <select id="atom-lan" v-model="form.lan[0]" class="inp" required>
          <option v-for="iface in view.ifaces" :key="iface.name" :value="iface.name">{{ iface.name }} · {{ iface.addrs.join('、') }}</option>
        </select>
      </div>
      <template v-else>
        <div class="field" role="group" aria-label="LAN 网卡">
          <span class="t2">LAN 网卡</span>
          <label v-for="iface in view.ifaces" :key="iface.name" class="row">
            <input v-model="form.lan" type="checkbox" :value="iface.name" :disabled="iface.name === form.wan" />
            {{ iface.name }} · {{ iface.addrs.join('、') }}
          </label>
        </div>
        <div class="field">
          <label for="atom-wan">WAN 网卡</label>
          <select id="atom-wan" v-model="form.wan" class="inp" required>
            <option value="" disabled>选择 WAN 网卡</option>
            <option v-for="iface in view.ifaces" :key="iface.name" :value="iface.name" :disabled="form.lan.includes(iface.name)">{{ iface.name }} · {{ iface.addrs.join('、') }}</option>
          </select>
        </div>
        <div class="field">
          <label for="atom-gateway">LAN 侧网关</label>
          <input id="atom-gateway" v-model.trim="form.lan_gateway" class="inp mono" placeholder="例：192.168.1.1" />
        </div>
        <div class="field">
          <label for="atom-client-nets">客户端网段（每行一个）</label>
          <textarea id="atom-client-nets" v-model.trim="form.client_nets" class="inp" placeholder="例：192.168.2.0/24"></textarea>
        </div>
        <label class="row">
          <input v-model="form.accept_gateway" type="checkbox" required />
          主路由会把需要代理的流量和 FakeIP 网段路由到 Atom
        </label>
      </template>
      <template v-if="form.topology === 'bypass'">
        <label class="row"><input v-model="form.reply_via" type="checkbox" /> 回包经主路由</label>
        <div v-if="form.reply_via" class="field">
          <label for="atom-router">主路由地址</label>
          <input id="atom-router" v-model.trim="form.router" class="inp mono" placeholder="例：192.168.1.1" required />
        </div>
      </template>
      <div class="field">
        <label for="atom-panel-port">面板端口</label>
        <input id="atom-panel-port" v-model.number="form.panel_port" class="inp mono" type="number" min="1" max="65535" required />
      </div>
    </fieldset>
  </form>
</template>

<style scoped>
.network-fields {
  gap: 12px;
  border: 0;
  min-width: 0;
  padding: 0;
  margin: 0;
}
</style>
