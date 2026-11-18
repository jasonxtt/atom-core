<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { call, client, describe, type Schemas } from '../api/client'
import { acceptMaintenanceJob, maintenance, maintenanceBusy, phaseLabels, refreshMaintenance } from '../composables/maintenance'

const job = computed(() => maintenance.value?.job)
const networkError = ref('')
const view = ref<Schemas['MaintenanceNetworkView'] | null>(null)
const form = ref<Schemas['MaintenanceNetwork'] | null>(null)
const networkChanged = computed(() => view.value && form.value &&
  JSON.stringify(view.value.config) !== JSON.stringify(form.value))
const urlLabel = (url: string) => new URL(url).host
// The new panel address lands on this card, where the change is confirmed.
function networkURL(url: string) {
  const target = new URL(url)
  target.hash = '/settings/network'
  return target.href
}
const newURLs = computed(() => job.value?.new_urls ?? [])
const networkJob = computed(() => job.value?.kind === 'network' ? job.value : undefined)
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
  <form class="card grid" style="gap: 12px" @submit.prevent="saveNetwork">
    <div class="hd" style="margin: 0">
      <h2>网络</h2>
      <span class="sp"></span>
      <button v-if="form" type="submit" class="btn pri sm" :disabled="!networkChanged || networkBusy || maintenanceBusy">试用并保存</button>
    </div>
    <div v-if="networkJob" class="grid" style="gap: 7px" aria-live="polite">
      <div>{{ phaseLabels[networkJob.phase] }}</div>
      <div v-if="networkJob.error" class="err">{{ networkJob.error }}</div>
      <template v-if="!networkJob.done && networkJob.phase !== 'restoring' && newURLs.length">
        <div class="t2">请在新面板地址确认。自检完成后有 3 分钟，超时会自动恢复。</div>
        <div v-if="deadline" class="t2">确认截止时间 {{ deadline }}</div>
        <div class="row" style="flex-wrap: wrap">
          <a v-for="url in newURLs" :key="url" class="btn sm" :href="networkURL(url)" target="_blank" rel="noopener noreferrer">{{ urlLabel(url) }}</a>
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
