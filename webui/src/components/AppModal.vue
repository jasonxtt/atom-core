<script setup lang="ts">
import { onMounted, onUnmounted } from 'vue'

defineProps<{ title: string }>()
const emit = defineEmits<{ close: [] }>()

const onKey = (event: KeyboardEvent) => {
  if (event.key === 'Escape') emit('close')
}
onMounted(() => document.addEventListener('keydown', onKey))
onUnmounted(() => document.removeEventListener('keydown', onKey))
</script>

<template>
  <Teleport to="body">
    <div class="mask" @click.self="emit('close')">
      <div class="modal" role="dialog" aria-modal="true" :aria-label="title">
        <h3><slot name="title">{{ title }}</slot></h3>
        <slot />
        <div class="ft"><slot name="footer" /></div>
      </div>
    </div>
  </Teleport>
</template>
