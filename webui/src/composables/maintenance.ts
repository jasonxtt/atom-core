import { computed, ref } from 'vue'
import { call, client, describe, type Schemas } from '../api/client'

export const maintenance = ref<Schemas['Maintenance'] | null>(null)
export const maintenanceError = ref('')
export const maintenanceBusy = computed(() => {
  const job = maintenance.value?.job
  return job !== undefined && (!job.done || job.blocking)
})

let request = 0

export async function refreshMaintenance() {
  const mine = ++request
  try {
    const next = await call(client.GET('/maintenance'))
    if (mine !== request) return
    const previousVersion = maintenance.value?.version
    maintenance.value = next
    maintenanceError.value = ''
    if (previousVersion && next.version !== previousVersion) window.location.reload()
  } catch (failure) {
    if (mine === request) maintenanceError.value = describe(failure)
  }
}

export function acceptMaintenanceJob(job: Schemas['MaintenanceJob']) {
  request++
  if (maintenance.value) maintenance.value = { ...maintenance.value, job }
}

export const phaseLabels: Record<Schemas['MaintenanceJob']['phase'], string> = {
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
