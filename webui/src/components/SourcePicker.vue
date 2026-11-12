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

const props = defineProps<{ label: string; namesOnly?: boolean; ipsOnly?: boolean }>()
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
    .map((item) => ({ id: item.id, name: item.name, provider: '默认', names: true, ips: false }))
  const remote = entries.value.map((entry) => ({ id: entry.id, name: entry.name, provider: PROVIDERS[entry.provider] ?? entry.provider, names: entry.names ?? null, ips: entry.ips ?? null }))
  return [...local, ...remote]
})

// With a client condition only names can be taken, with a port or network condition only IP
// prefixes: a source without that part is unusable.
const usable = (source: Source) => (!props.namesOnly || source.names !== false) && (!props.ipsOnly || source.ips !== false)

// Keyboard: the arrows move the active option, Enter picks it, Escape closes the list.
const active = ref(-1)
const listId = `source-${Math.random().toString(36).slice(2, 8)}`
watch(options, () => (active.value = -1))
function move(step: number) {
  open.value = true
  const count = options.value.length
  if (!count) return
  let next = active.value
  for (let tries = 0; tries < count; tries++) {
    next = (next + step + count) % count
    if (usable(options.value[next])) {
      active.value = next
      return
    }
  }
}
function enter() {
  const source = options.value[active.value]
  if (open.value && source && usable(source)) pick(source)
}

const parts = (source: Source) =>
  source.names === null ? '' : [source.names ? '域名' : '', source.ips ? 'IP' : ''].filter(Boolean).join(' · ')

function pick(source: Source) {
  if (!usable(source)) return
  open.value = false
  emit('pick', source)
}
</script>

<template>
  <div class="combo">
    <input
      v-model="query"
      class="inp"
      placeholder="搜索内置规则集，例如 netflix、telegram、cn"
      :aria-label="label"
      autocomplete="off"
      role="combobox"
      aria-autocomplete="list"
      :aria-controls="listId"
      :aria-expanded="open"
      :aria-activedescendant="open && active >= 0 ? `${listId}-${active}` : undefined"
      @focus="open = true"
      @click="open = true"
      @input="open = true"
      @keydown.down.prevent="move(1)"
      @keydown.up.prevent="move(-1)"
      @keydown.enter.prevent="enter"
      @keydown.esc="open = false"
      @blur="open = false"
    />
    <div v-if="open" :id="listId" class="drop" role="listbox" :aria-label="label">
      <button
        v-for="(source, index) in options"
        :id="`${listId}-${index}`"
        :key="source.id"
        type="button"
        tabindex="-1"
        class="opt"
        :class="{ active: index === active }"
        role="option"
        :aria-selected="index === active"
        :aria-disabled="!usable(source)"
        :disabled="!usable(source)"
        @mousedown.prevent="pick(source)"
      >
        <span class="nm">{{ source.name }}</span>
        <span class="tag">{{ source.provider }}</span>
        <span class="hint">{{ parts(source) }}</span>
      </button>
      <div v-if="error" class="hint" style="padding: 8px 10px; color: var(--bad)">{{ error }}</div>
      <div v-else-if="!options.length" class="hint" style="padding: 8px 10px">没有匹配的规则集</div>
      <div v-else-if="total > entries.length" class="hint" style="padding: 6px 10px">目录里还有 {{ total - entries.length }} 项，请输入更多字</div>
    </div>
  </div>
</template>
