<script setup lang="ts">
import { nextTick, onMounted, onUnmounted, ref } from 'vue'

defineProps<{ title: string }>()
const emit = defineEmits<{ close: [] }>()

const dialog = ref<HTMLElement | null>(null)
// Focus moves into the dialog, stays inside it while it is open, and goes back to what had it.
const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null
const FOCUSABLE = 'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), summary, [tabindex]:not([tabindex="-1"])'

function focusable(): HTMLElement[] {
  return dialog.value ? [...dialog.value.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((item) => item.offsetParent !== null) : []
}

function onKey(event: KeyboardEvent) {
  if (event.key === 'Escape') {
    emit('close')
    return
  }
  if (event.key !== 'Tab') return
  const items = focusable()
  if (!items.length) {
    event.preventDefault()
    dialog.value?.focus()
    return
  }
  const first = items[0]
  const last = items[items.length - 1]
  const inside = dialog.value?.contains(document.activeElement)
  if (event.shiftKey && (document.activeElement === first || !inside)) {
    event.preventDefault()
    last.focus()
  } else if (!event.shiftKey && (document.activeElement === last || !inside)) {
    event.preventDefault()
    first.focus()
  }
}

onMounted(async () => {
  document.addEventListener('keydown', onKey)
  await nextTick()
  const items = focusable()
  ;(items.find((item) => item.matches('input, textarea, select')) ?? items[0] ?? dialog.value)?.focus()
})
onUnmounted(() => {
  document.removeEventListener('keydown', onKey)
  if (opener?.isConnected) opener.focus()
})
</script>

<template>
  <Teleport to="body">
    <div class="mask" @click.self="emit('close')">
      <div ref="dialog" class="modal" role="dialog" aria-modal="true" :aria-label="title" tabindex="-1">
        <h3><slot name="title">{{ title }}</slot></h3>
        <slot />
        <div class="ft"><slot name="footer" /></div>
      </div>
    </div>
  </Teleport>
</template>
