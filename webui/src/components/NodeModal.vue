<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import { ApiError, call, client, describe } from '../api/client'
import AppModal from './AppModal.vue'
import { FINAL, FINAL_NAME, final, groups, loadProxy, nodes, version, type Node } from '../composables/proxy'
import { refreshStatus } from '../composables/status'
import { toast } from '../composables/toast'

/** Import nodes (no `node`), or rename / replace one. */
const props = defineProps<{ node?: Node }>()
const emit = defineEmits<{ close: [] }>()

type Format = 'link' | 'yaml' | 'json'
const formats: [Format, string][] = [
  ['link', '分享链接'],
  ['yaml', 'Clash YAML'],
  ['json', 'sing-box JSON']
]
const placeholders: Record<Format, string> = {
  link: 'vless://…\nhy2://…\nss://…',
  yaml: 'proxies:\n  - name: …\n    type: vless\n    …',
  json: '{ "type": "vless", "server": "…", … }'
}

const form = reactive({
  name: props.node?.name ?? '',
  replace: false,
  format: 'link' as Format,
  content: '',
  join: true,
  joinGroup: 'g-default'
})
const error = ref('')
const busy = ref(false)
// The version the dialog opened at; an edit carries it, so a change made elsewhere since is
// refused (409) instead of being overwritten.
const formVersion = ref(version.value)
// After a 409 on an edit: the node as it is saved now (null when it was deleted).
const conflict = ref<Node | null | undefined>(undefined)
// The node the form edits from: the one opened, or the one saved now after "载入最新内容" or
// "仍然保存" (what a change of name is compared with, and the connection shown).
const base = ref<Node | undefined>(props.node)

/** Drops the edits and starts again from the node as saved now. */
function reload(current: Node) {
  base.value = current
  form.name = current.name
  form.replace = false
  form.content = ''
  formVersion.value = version.value
  conflict.value = undefined
  error.value = ''
}
const joinTargets = computed(() => [...groups.value.map((group) => ({ id: group.id, name: group.name })), { id: FINAL, name: FINAL_NAME }])
const outbound = computed(() => JSON.stringify(base.value?.outbound ?? {}, null, 2))

function stale(failure: unknown) {
  return failure instanceof ApiError && failure.status === 409 && failure.body?.version !== undefined
}

/**
 * Adds imported nodes to a group (or Final), keeping its other fields. It reads the state
 * again first, so the members and the version it writes are the current ones.
 */
async function join(ids: string[]) {
  await loadProxy()
  const at = version.value
  if (form.joinGroup === FINAL) {
    const members = [...(final.value?.members ?? []), ...ids]
    await call(client.PUT('/final', { body: { members, version: at } }))
    return
  }
  const group = groups.value.find((item) => item.id === form.joinGroup)
  if (!group) throw new Error('这个节点组已不存在')
  const { name, type, selected, url, interval, tolerance } = group
  await call(
    client.PUT('/groups/{id}', {
      params: { path: { id: group.id } },
      body: { name, type, selected, url, interval, tolerance, members: [...group.members, ...ids], version: at }
    })
  )
}

async function submit(overwrite = false) {
  error.value = ''
  if (overwrite) {
    if (conflict.value) base.value = conflict.value
    formVersion.value = version.value
    conflict.value = undefined
  }
  const content = form.content.trim()
  busy.value = true
  try {
    if (props.node) {
      const body: { name?: string; format?: Format; content?: string; version: number } = { version: formVersion.value }
      if (form.name.trim() && form.name.trim() !== base.value?.name) body.name = form.name.trim()
      if (form.replace) {
        if (!content) throw new Error('请粘贴新的连接')
        body.format = form.format
        body.content = content
      }
      await call(client.PUT('/nodes/{id}', { params: { path: { id: props.node.id } }, body }))
      toast('ok', '已保存')
    } else {
      if (!content) throw new Error('请先粘贴节点')
      const answer = await call(client.POST('/nodes', { body: { format: form.format, content, version: formVersion.value } }))
      const ids = answer.nodes.map((node) => node.id)
      let joined = ''
      if (form.join && ids.length) {
        try {
          await join(ids)
          joined = `，已加入「${joinTargets.value.find((item) => item.id === form.joinGroup)?.name ?? ''}」`
        } catch (failure) {
          toast('bad', `节点已导入，但没有加入节点组：${failure instanceof ApiError ? describe(failure) : failure instanceof Error ? failure.message : String(failure)}`)
        }
      }
      toast('ok', `导入了 ${ids.length} 个节点${joined}`)
    }
    await loadProxy().catch(() => {})
    emit('close')
  } catch (failure) {
    if (stale(failure)) {
      await loadProxy().catch(() => {})
      if (props.node) {
        conflict.value = nodes.value.find((item) => item.id === props.node?.id) ?? null
        if (!conflict.value) error.value = '这个节点已在别处删除（409）'
      } else {
        // An import adds nodes and overwrites nothing: the next one carries the current version.
        formVersion.value = version.value
        error.value = '节点或节点组已在别处修改，已载入最新版本，请再提交一次（409）'
      }
    } else {
      error.value = failure instanceof ApiError ? describe(failure) : failure instanceof Error ? failure.message : String(failure)
    }
  } finally {
    busy.value = false
    refreshStatus().catch(() => {})
  }
}
</script>

<template>
  <AppModal :title="node ? '编辑节点' : '添加节点'" @close="emit('close')">
    <template v-if="node">
      <div class="field">
        <label for="nname">名称</label>
        <input id="nname" v-model="form.name" class="inp" autocomplete="off" />
      </div>
      <div class="tile">
        <div class="k">当前连接</div>
        <div class="v mono" style="font-size: 13px">{{ base?.type }} · {{ base?.server }}:{{ base?.server_port }}</div>
      </div>
      <details>
        <summary class="t2">连接参数</summary>
        <pre class="json" style="margin-top: 8px">{{ outbound }}</pre>
      </details>
      <label class="row"><input v-model="form.replace" type="checkbox" /> 替换连接</label>
    </template>
    <template v-if="!node || form.replace">
      <div class="seg" style="align-self: flex-start">
        <button v-for="item in formats" :key="item[0]" type="button" :class="{ on: form.format === item[0] }" @click="form.format = item[0]">{{ item[1] }}</button>
      </div>
      <textarea v-model="form.content" class="inp" style="min-height: 140px" :placeholder="placeholders[form.format]" aria-label="节点内容"></textarea>
    </template>
    <label v-if="!node" class="row">
      <input v-model="form.join" type="checkbox" /> 导入后加入组
      <select v-model="form.joinGroup" class="inp" style="width: auto" aria-label="加入的组" :disabled="!form.join">
        <option v-for="item in joinTargets" :key="item.id" :value="item.id">{{ item.name }}</option>
      </select>
    </label>
    <template v-if="conflict">
      <div class="err">已在别处修改（409）。现在保存的是：</div>
      <div class="tile" style="font-size: 12.5px">
        <div>{{ conflict.name }}</div>
        <div class="t2 mono">{{ conflict.type }} · {{ conflict.server }}:{{ conflict.server_port }}</div>
      </div>
    </template>
    <div v-if="error" class="err">{{ error }}</div>
    <template #footer>
      <template v-if="conflict">
        <button class="btn" type="button" @click="reload(conflict)">载入最新内容</button>
        <button class="btn red" type="button" :disabled="busy" @click="submit(true)">仍然保存</button>
      </template>
      <template v-else>
        <button class="btn" type="button" @click="emit('close')">取消</button>
        <button class="btn pri" type="button" :disabled="busy" @click="submit()">{{ node ? '保存' : '导入' }}</button>
      </template>
    </template>
  </AppModal>
</template>
