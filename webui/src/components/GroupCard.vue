<script setup lang="ts">
import { computed } from 'vue'
import { call, client } from '../api/client'
import { testGroup, testNode, testing } from '../composables/delay'
import { currentOf, delayOf, FINAL, isGroup, leafOf, loadProxy, loadRuntime, nameOf, nodes, reportFailure, version, type GroupView } from '../composables/proxy'
import { latency, latencyText, rate } from '../format'

const props = defineProps<{ view: GroupView; open?: boolean; editing?: boolean; traffic?: number }>()
const emit = defineEmits<{ toggle: []; edit: []; remove: [] }>()

const current = computed(() => currentOf(props.view.id))
const tag = computed(() => (props.view.id === FINAL ? '兜底' : props.view.builtin ? '默认' : ''))
const typeLabel = computed(() => (props.view.type === 'selector' ? '手动' : '自动测速'))

function lat(id: string | undefined) {
  const test = delayOf(id)
  return { kind: latency(test?.delay, test?.time), text: latencyText(test?.delay, test?.time) }
}
const head = computed(() => lat(current.value))

function subOf(id: string) {
  if (isGroup(id)) return `组 · ${nameOf(leafOf(id))}`
  return nodes.value.find((node) => node.id === id)?.type ?? ''
}

async function select(member: string) {
  if (props.view.type !== 'selector' || member === current.value) return
  try {
    const answer = await call(client.POST('/groups/{id}/select', { params: { path: { id: props.view.id } }, body: { name: member, version: version.value } }))
    version.value = answer.version
  } catch (error) {
    await reportFailure(error)
  } finally {
    // The saved choice changed too (the edit form starts from it).
    await Promise.all([loadRuntime(), loadProxy().catch(() => {})])
  }
}

/** A node's tag tests that node; a group's tag tests the node it uses now. */
function testMember(member: string) {
  const leaf = leafOf(member)
  if (leaf) void testNode(leaf, leaf === member ? leaf : `m:${member}`)
}
const memberTesting = (member: string) => testing[isGroup(member) ? `m:${member}` : member]
</script>

<template>
  <div class="gcard">
    <div class="ghead" @click="!editing && emit('toggle')">
      <span v-if="editing" class="handle" aria-hidden="true">⠿</span>
      <span class="nm">{{ view.name }}</span>
      <span class="ty">{{ typeLabel }} · {{ view.members.length }}</span>
      <span v-if="tag" class="tag">{{ tag }}</span>
      <span class="sp"></span>
      <template v-if="editing">
        <button class="ico" type="button" aria-label="编辑" title="编辑" @click.stop="emit('edit')">
          <svg viewBox="0 0 24 24"><path d="M4 20h4L19 9l-4-4L4 16z" /></svg>
        </button>
        <button v-if="!view.builtin" class="ico" type="button" aria-label="删除" title="删除" style="color: var(--bad)" @click.stop="emit('remove')">
          <svg viewBox="0 0 24 24"><path d="M5 7h14M9 7V4h6v3M7 7l1 13h8l1-13" /></svg>
        </button>
      </template>
      <template v-else>
        <button class="lat" :class="head.kind" type="button" :title="`整组测速：${view.name}`" @click.stop="testGroup(view.id)">
          {{ testing[`g:${view.id}`] ? '…' : head.kind === 'idle' ? '测速' : head.text }}
        </button>
        <button
          class="ico"
          type="button"
          style="width: 24px; height: 24px"
          :aria-expanded="!!open"
          :aria-label="`${open ? '收起' : '展开'}：${view.name}`"
          @click.stop="emit('toggle')"
        >
          {{ open ? '▴' : '▾' }}
        </button>
      </template>
    </div>
    <div class="gnow">
      <span>→</span>
      <span class="cur">{{ nameOf(current) }}</span>
      <span v-if="current && isGroup(current)" class="tag">组</span>
      <span class="sp"></span>
      <span v-if="traffic !== undefined" class="tnum" style="font-size: 12px">{{ rate(traffic) }}</span>
    </div>
    <div v-if="!open || editing" class="dots">
      <span v-for="member in view.members" :key="member" class="sq" :class="[lat(member).kind, { cur: member === current }]" :title="nameOf(member)"></span>
      <span v-if="!view.members.length" class="hint" style="color: var(--bad)">空组</span>
    </div>
    <div v-else class="mtiles">
      <button
        v-for="member in view.members"
        :key="member"
        type="button"
        class="mtile"
        :class="{ cur: member === current, static: view.type !== 'selector' }"
        @click="select(member)"
      >
        <span class="nm">{{ nameOf(member) }}</span>
        <span class="ft">
          <span class="sub">{{ subOf(member) }}</span>
          <span
            class="lat"
            :class="lat(member).kind"
            role="button"
            tabindex="0"
            :title="isGroup(member) ? `测速：${nameOf(leafOf(member))}` : '测速'"
            @click.stop="testMember(member)"
            @keydown.enter.stop.prevent="testMember(member)"
          >{{ memberTesting(member) ? '…' : lat(member).kind === 'idle' ? '测速' : lat(member).text }}</span>
        </span>
      </button>
      <span v-if="!view.members.length" class="hint" style="color: var(--bad)">空组</span>
    </div>
  </div>
</template>
