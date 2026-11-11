import { onMounted, onUnmounted } from 'vue'

/**
 * Runs `task` now and then every `ms` while the component is mounted; a run starts only
 * after the previous one finished, and none run while the page is hidden.
 */
export function usePoll(task: () => Promise<void>, ms: number) {
  let timer: ReturnType<typeof setTimeout> | undefined
  let stopped = false
  const run = async () => {
    if (stopped) return
    if (!document.hidden) {
      try {
        await task()
      } catch {
        // the task shows its own failures
      }
    }
    if (!stopped) timer = setTimeout(run, ms)
  }
  onMounted(run)
  onUnmounted(() => {
    stopped = true
    clearTimeout(timer)
  })
}
