<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from 'vue'
import { call, client, describe, type Schemas } from '../api/client'
import { builtins } from '../composables/rules'

/** A rule source picked: a builtin set or a catalog entry (`names`/`ips` null: unknown yet). */
export interface Source {
  id: string
  name: string
  provider: string
  names: boolean | null
  ips: boolean | null
}

defineProps<{ label: string }>()
const emit = defineEmits<{ pick: [source: Source] }>()

const PROVIDERS: Record<string, string> = { meta: 'MetaCubeX', bm7: 'blackmatrix7' }
const query = ref('')
const open = ref(false)
const entries = ref<Schemas['CatalogEntry'][]>([])
const total = ref(0)
const error = ref('')
let timer: ReturnType<typeof setTimeout> | undefined
let asked = 0

// The catalog is searched on the server (debounced); the builtin sets here.
watch(query, (text) => {
  clearTimeout(timer)
  timer = setTimeout(async () => {
    const ticket = ++asked
    try {
      const answer = await call(client.GET('/catalog', { params: { query: { q: text.trim(), limit: 30 } } }))
      if (ticket !== asked) return
      entries.value = answer.entries
      total.value = answer.total
      error.value = ''
    } catch (failure) {
      if (ticket === asked) error.value = describe(failure)
    }
  }, 250)
}, { immediate: true })
onUnmounted(() => clearTimeout(timer))

const options = computed<Source[]>(() => {
  const text = query.value.trim().toLowerCase()
  const local = builtins.value
    .filter((item) => item.usable && (!text || `${item.id} ${item.name}`.toLowerCase().includes(text)))
    .map((item) => ({ id: item.id, name: item.name, provider: '内置', names: true, ips: false }))
  const remote = entries.value.map((entry) => ({ id: entry.id, name: entry.name, provider: PROVIDERS[entry.provider] ?? entry.provider, names: entry.names ?? null, ips: entry.ips ?? null }))
  return [...local, ...remote]
})

const parts = (source: Source) =>
  source.names === null ? '' : [source.names ? '域名' : '', source.ips ? 'IP' : ''].filter(Boolean).join(' · ')

function pick(source: Source) {
  open.value = false
  emit('pick', source)
}
</script>

<template>
  <div class="combo">
    <input
      v-model="query"
      class="inp"
      placeholder="搜索规则源，例如 netflix、telegram、cn"
      :aria-label="label"
      autocomplete="off"
      role="combobox"
      :aria-expanded="open"
      @focus="open = true"
      @click="open = true"
      @input="open = true"
      @keydown.esc="open = false"
      @blur="open = false"
    />
    <div v-if="open" class="drop" role="listbox">
      <button v-for="source in options" :key="source.id" type="button" class="opt" role="option" @mousedown.prevent="pick(source)">
        <span class="nm">{{ source.name }}</span>
        <span class="tag">{{ source.provider }}</span>
        <span class="hint">{{ parts(source) }}</span>
      </button>
      <div v-if="error" class="hint" style="padding: 8px 10px; color: var(--bad)">{{ error }}</div>
      <div v-else-if="!options.length" class="hint" style="padding: 8px 10px">没有匹配的规则源</div>
      <div v-else-if="total > entries.length" class="hint" style="padding: 6px 10px">目录里还有 {{ total - entries.length }} 项，请输入更多字</div>
    </div>
  </div>
</template>
