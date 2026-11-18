<script setup lang="ts">
import { computed, ref } from 'vue'
import { call, client, describe } from '../api/client'
import { acceptMaintenanceJob, maintenance, maintenanceBusy, maintenanceError, phaseLabels, refreshMaintenance } from '../composables/maintenance'

const job = computed(() => maintenance.value?.job)
const checking = ref(false)
const updateError = ref('')
const latest = computed(() => job.value?.kind === 'check' && job.value.phase === 'success' ? job.value.version : undefined)
const latestNotes = computed(() => latest.value ? `https://github.com/jasonxtt/atom/releases/tag/v${latest.value}` : '')
const updateJob = computed(() => job.value?.kind !== 'network' ? job.value : undefined)

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
      <button type="button" class="btn" :disabled="checking || maintenanceBusy" @click="update('check')">检查更新</button>
      <a v-if="latestNotes" class="btn" :href="latestNotes" target="_blank" rel="noopener noreferrer">发布说明</a>
      <button v-if="latest" type="button" class="btn pri" :disabled="checking || maintenanceBusy" @click="update('upgrade')">升级 Atom</button>
    </div>
    <div v-else-if="!maintenance && maintenanceError"><button type="button" class="btn" @click="refreshMaintenance">重试</button></div>
  </div>
</template>
