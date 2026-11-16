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
