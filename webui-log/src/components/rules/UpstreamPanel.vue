<script setup>
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { getJSON, getText, postJSON } from '../../api/http'
import { isNativeUpstreamReadOnly, nativeUpstreamProtocol } from '../../api/nativeManagement'
import { getRuntimeCapabilities, operationReason, supportsOperation } from '../../api/runtimeCapabilities'
import { openConfirm } from '../../utils/confirm'
import { isModified, settingsBackedProxy, settingsSources } from '../../utils/nativeSettings'
import { clearTopNotice, setError, setSuccess } from '../../utils/notice'
import { latencyTone } from '../../utils/overviewMetrics'
import { lastUpstreamReason, loadUpstreamGroups, orderUpstreamGroups, parseUpstreamStatsMetrics, protocolDisplayLabel, upstreamAddressDisplay, upstreamGroupDisplay } from '../../utils/upstreamStats'
import AppIcon from '../AppIcon.vue'
import UpstreamEditorModal from './UpstreamEditorModal.vue'

// The upstream list by group: identifier, protocol, address, enabled and latency; every
// other parameter is in the edit dialog. The upstreams that belong to a special group are
// listed read-only with a link to the group. Groups not in use under the current switches
// (`show_when` in the configuration) are hidden unless "显示未生效的组" is on.
const loading = ref(false)
const upstreamConfig = ref({})
const specialGroups = ref([])
const capabilities = ref(null)
const sourceMarks = ref({})
const stats = ref({})
const globalSocks5 = ref('')
const editor = reactive({ open: false, group: '', index: -1, entry: null })
const HIDE_DISABLED_KEY = 'atomdns-hide-disabled-upstreams'
const SHOW_INACTIVE_KEY = 'atomdns-show-inactive-upstream-groups'
const filterGroup = ref('all')
const hideDisabled = ref(false)
const showInactive = ref(false)
// tag → { active, inactive_reason } from /api/v1/upstream/groups (empty: every group is in use).
const groupStates = ref({})
const sort = reactive({ key: '', order: 'asc' })

const canManage = computed(() => supportsOperation('upstreams.manage'))
const settingsProxy = computed(() => settingsBackedProxy(capabilities.value))
const configuredGroups = computed(() => orderUpstreamGroups(Object.keys(upstreamConfig.value).filter((group) => !/^special_upstream_\d+$/.test(group)), specialGroups.value))
const inactive = (group) => groupStates.value[group]?.active === false
const inactiveCount = computed(() => configuredGroups.value.filter(inactive).length)
const allGroups = computed(() => configuredGroups.value.filter((group) => showInactive.value || !inactive(group)))
const groups = computed(() => allGroups.value.filter((group) => filterGroup.value === 'all' || group === filterGroup.value))
const specialRows = computed(() => specialGroups.value.map((group) => {
  const list = upstreamConfig.value[group.upstream_plugin_tag]
  const owned = Array.isArray(group.owned_upstreams) ? group.owned_upstreams.length : 0
  return { slot: group.slot, name: group.name, owned, effective: group.effective_upstream_count || 0, listed: Array.isArray(list) ? list.length : 0 }
}))

const collator = new Intl.Collator('zh-CN', { numeric: true, sensitivity: 'base' })
const sortValue = (row) => {
  switch (sort.key) {
    case 'tag': return String(row.entry.tag || '')
    case 'protocol': return String(row.entry.protocol || '')
    case 'address': return upstreamAddressDisplay(row.entry)
    case 'enabled': return row.entry.enabled ? '1' : '0'
    default: return ''
  }
}

function onSort(key) {
  if (sort.key === key) sort.order = sort.order === 'asc' ? 'desc' : 'asc'
  else Object.assign(sort, { key, order: 'asc' })
}

const sortMark = (key) => (sort.key !== key ? '' : sort.order === 'asc' ? '▲' : '▼')

function toggleShowInactive() {
  showInactive.value = !showInactive.value
  try {
    localStorage.setItem(SHOW_INACTIVE_KEY, showInactive.value ? '1' : '0')
  } catch {
    // the choice only lasts for this page
  }
}

function toggleHideDisabled() {
  hideDisabled.value = !hideDisabled.value
  try {
    localStorage.setItem(HIDE_DISABLED_KEY, hideDisabled.value ? '1' : '0')
  } catch {
    // the choice only lasts for this page
  }
}

function rowsOf(group) {
  const list = Array.isArray(upstreamConfig.value[group]) ? upstreamConfig.value[group] : []
  const rows = list.map((entry, index) => {
    const stat = stats.value[`${group}|${entry?.tag || ''}`] || {}
    const latency = Number(stat.latencyCount) > 0 ? Number(stat.latencySum) / Number(stat.latencyCount) : null
    return {
      index,
      entry: entry || {},
      status: isNativeUpstreamReadOnly(entry || {}, capabilities.value),
      latency,
      tone: latency === null ? '' : latencyTone(latency)
    }
  })
  const shown = hideDisabled.value ? rows.filter((row) => row.entry.enabled || row.status.readOnly) : rows
  if (!sort.key) return shown
  const sorted = [...shown].sort((a, b) => collator.compare(sortValue(a), sortValue(b)) || a.index - b.index)
  return sort.order === 'asc' ? sorted : sorted.reverse()
}

function groupTitle(group) {
  return upstreamGroupDisplay(group, specialGroups.value).title
}

const modifiedGroup = (group) => isModified(sourceMarks.value[group])

async function load() {
  if (!supportsOperation('upstreams.read')) return
  loading.value = true
  try {
    capabilities.value = await getRuntimeCapabilities()
    const [config, groupList] = await Promise.all([
      getJSON('/api/v1/upstream/config'),
      supportsOperation('groups.read') ? getJSON('/api/v1/special-groups') : Promise.resolve([])
    ])
    upstreamConfig.value = config && typeof config === 'object' && !Array.isArray(config) ? config : {}
    specialGroups.value = Array.isArray(groupList) ? groupList : []
    groupStates.value = await loadUpstreamGroups(getJSON, capabilities.value)
    const [effective, metrics, overrides] = await Promise.allSettled([
      getJSON('/api/v1/settings/effective'),
      supportsOperation('metrics.cache') ? getText('/metrics') : Promise.reject(new Error('unavailable')),
      supportsOperation('system.global_overrides') ? getJSON('/api/v1/overrides') : Promise.reject(new Error('unavailable'))
    ])
    sourceMarks.value = effective.status === 'fulfilled' ? settingsSources(effective.value).upstreams : {}
    stats.value = metrics.status === 'fulfilled' ? parseUpstreamStatsMetrics(metrics.value) : {}
    globalSocks5.value = overrides.status === 'fulfilled' ? String(overrides.value?.socks5 || '').trim() : ''
  } catch (error) {
    setError(`读取上游配置失败: ${error.message}`)
  } finally {
    loading.value = false
  }
}

async function saveGroup(group, list) {
  await postJSON('/api/v1/upstream/config', { plugin_tag: group, upstreams: list })
}

function beginAdd(group) {
  clearTopNotice()
  Object.assign(editor, { open: true, group, index: -1, entry: null })
}

function beginEdit(group, row) {
  clearTopNotice()
  if (row.status.readOnly) return setError(row.status.reason || '这条上游包含当前版本不支持的配置，保持只读')
  Object.assign(editor, { open: true, group, index: row.index, entry: row.entry })
}

async function onSave(entry) {
  const group = editor.group
  try {
    const list = [...(upstreamConfig.value[group] || [])]
    if (editor.index >= 0) list[editor.index] = { ...entry, enabled: Boolean(list[editor.index]?.enabled) }
    else list.push({ ...entry, enabled: true })
    await saveGroup(group, list)
    setSuccess('上游配置已保存')
    editor.open = false
    await load()
  } catch (error) {
    setError(`保存失败: ${error.message}`)
  }
}

// Why a change would leave `group` without an enabled upstream (refused before sending).
const refusal = (group, list) => lastUpstreamReason(group, list, groupStates.value[group], groupTitle(group))

// After a refused or failed change the switch shows what the host has again (the data did not
// change, so Vue would leave the clicked checkbox as it is).
function resetSwitch(input, group, index) {
  if (input) input.checked = Boolean(upstreamConfig.value[group]?.[index]?.enabled)
}

async function toggle(group, row, event) {
  const input = event?.target
  if (row.status.readOnly) {
    resetSwitch(input, group, row.index)
    return setError(row.status.reason || '保持只读')
  }
  clearTopNotice()
  const list = [...upstreamConfig.value[group]]
  list[row.index] = { ...list[row.index], enabled: !list[row.index].enabled }
  const reason = refusal(group, list)
  if (reason) {
    resetSwitch(input, group, row.index)
    return setError(reason)
  }
  try {
    await saveGroup(group, list)
  } catch (error) {
    setError(`切换失败: ${error.message}`)
  }
  await load()
  resetSwitch(input, group, row.index)
}

async function remove(group, row) {
  if (row.status.readOnly) return setError(row.status.reason || '保持只读')
  const list = [...upstreamConfig.value[group]]
  list.splice(row.index, 1)
  // An empty list would mean "restore the configuration file's list", not "delete".
  const reason = refusal(group, list)
  if (reason) return setError(reason)
  if (!(await openConfirm(`确定删除上游“${row.entry.tag || '未命名'}”吗？`, { tone: 'danger' }))) return
  try {
    await saveGroup(group, list)
    setSuccess('上游已删除')
    await load()
  } catch (error) {
    setError(`删除失败: ${error.message}`)
  }
}

async function restore(group) {
  if (!(await openConfirm(`确定把“${groupTitle(group)}”的上游恢复为配置文件里的默认列表吗？`))) return
  try {
    await postJSON('/api/v1/upstream/config', { plugin_tag: group, upstreams: [] })
    setSuccess('已恢复默认上游列表')
    await load()
  } catch (error) {
    setError(`恢复默认失败: ${error.message}`)
  }
}

onMounted(() => {
  try {
    hideDisabled.value = localStorage.getItem(HIDE_DISABLED_KEY) === '1'
    showInactive.value = localStorage.getItem(SHOW_INACTIVE_KEY) === '1'
  } catch {
    hideDisabled.value = false
    showInactive.value = false
  }
  load()
  window.addEventListener('atomdns-log-refresh', load)
})
onBeforeUnmount(() => window.removeEventListener('atomdns-log-refresh', load))
</script>

<template>
  <section class="panel rt-upstreams" data-upstream-panel>
    <header class="rt-list-head">
      <div class="rt-list-title"><h3>上游列表</h3></div>
      <div class="rt-learning-controls" v-if="supportsOperation('upstreams.read')">
        <select v-model="filterGroup" class="rt-setting-input" aria-label="按组筛选">
          <option value="all">全部分组</option>
          <option v-for="group in allGroups" :key="group" :value="group">{{ groupTitle(group) }}</option>
        </select>
        <button class="btn secondary" type="button" @click="toggleHideDisabled">{{ hideDisabled ? '显示全部上游' : '隐藏未启用上游' }}</button>
        <button v-if="inactiveCount > 0" class="btn secondary" type="button" data-show-inactive @click="toggleShowInactive">{{ showInactive ? '隐藏未生效的组' : `显示未生效的组（${inactiveCount}）` }}</button>
      </div>
    </header>
    <p v-if="!supportsOperation('upstreams.read')" class="muted" role="note">{{ operationReason('upstreams.read') }}</p>
    <template v-else>
      <p v-if="!canManage" class="muted" role="note">{{ operationReason('upstreams.manage') }}</p>
      <p v-if="loading && groups.length === 0" class="muted">读取中…</p>
      <p v-else-if="groups.length === 0" class="muted">暂无上游配置</p>
      <div v-if="groups.length > 0" class="flat-table-wrap">
        <table class="flat-table rt-upstream-table">
          <thead>
            <tr>
              <th class="sortable" @click="onSort('tag')">标识 {{ sortMark('tag') }}</th>
              <th class="sortable" @click="onSort('protocol')">协议 {{ sortMark('protocol') }}</th>
              <th class="sortable" @click="onSort('address')">地址 {{ sortMark('address') }}</th>
              <th class="rt-col-switch sortable" @click="onSort('enabled')">启用 {{ sortMark('enabled') }}</th>
              <th class="text-right">延迟</th>
              <th class="rt-col-actions">操作</th>
            </tr>
          </thead>
          <tbody v-for="group in groups" :key="group" :data-group="group">
            <tr class="rt-upstream-group-row">
              <td colspan="6">
                <div class="rt-upstream-group-head">
                  <strong>{{ groupTitle(group) }}</strong>
                  <span class="muted">{{ (upstreamConfig[group] || []).length }} 个</span>
                  <span v-if="modifiedGroup(group)" class="rt-flag-mark" data-native-modified>已修改</span>
                  <span v-if="inactive(group)" class="rt-flag-mark" data-inactive-group :title="groupStates[group]?.inactive_reason || ''">当前未生效</span>
                  <span class="rt-upstream-group-actions">
                    <button v-if="modifiedGroup(group)" class="btn tiny secondary" type="button" :disabled="!canManage" @click="restore(group)">恢复默认</button>
                    <button class="btn tiny primary" type="button" :disabled="!canManage" @click="beginAdd(group)">添加</button>
                  </span>
                </div>
              </td>
            </tr>
            <tr v-if="rowsOf(group).length === 0"><td colspan="6" class="empty">{{ hideDisabled ? '这个组没有已启用的上游' : '这个组还没有上游' }}</td></tr>
            <tr v-for="row in rowsOf(group)" :key="`${group}-${row.index}-${row.entry.tag}`" :class="{ disabled: !row.entry.enabled || row.status.readOnly }">
              <td :title="row.entry.tag">{{ row.entry.tag || '-' }}<span v-if="row.status.readOnly" class="muted" :title="row.status.reason">（只读）</span></td>
              <td>{{ protocolDisplayLabel(nativeUpstreamProtocol(row.entry)) }}</td>
              <td class="mono" :title="upstreamAddressDisplay(row.entry)">{{ upstreamAddressDisplay(row.entry) }}</td>
              <td class="rt-col-switch">
                <label class="switch switch-table">
                  <input type="checkbox" :checked="Boolean(row.entry.enabled)" :disabled="!canManage || row.status.readOnly" :aria-label="`启用 ${row.entry.tag}`" @change="toggle(group, row, $event)" />
                  <span class="slider"></span>
                </label>
              </td>
              <td class="text-right" :class="row.tone ? `rt-text-${row.tone}` : ''">{{ row.latency === null ? '-' : `${row.latency.toFixed(1)} ms` }}</td>
              <td class="rt-col-actions">
                <div class="rt-row-actions">
                  <button class="rt-row-icon" type="button" title="编辑" :aria-label="`编辑 ${row.entry.tag}`" :disabled="!canManage || row.status.readOnly" @click="beginEdit(group, row)">
                    <AppIcon name="pencil" :size="16" />
                  </button>
                  <button class="rt-row-icon danger" type="button" title="删除" :aria-label="`删除 ${row.entry.tag}`" :disabled="!canManage || row.status.readOnly" @click="remove(group, row)">
                    <AppIcon name="trash" :size="16" />
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div v-if="specialRows.length > 0" class="rt-upstream-special" data-special-upstreams>
        <strong>专属分流组的上游</strong>
        <p class="muted rt-list-hint">专属分流组使用自己的上游，只在这里显示，到组里管理。</p>
        <ul class="rt-link-list">
          <li v-for="row in specialRows" :key="row.slot">
            <span>{{ row.name }}：生效 {{ row.effective }} 个上游</span>
            <router-link :to="{ path: '/rules/special-groups', query: { group: String(row.slot) } }" class="btn tiny secondary">管理</router-link>
          </li>
        </ul>
      </div>
    </template>
    <UpstreamEditorModal
      v-if="editor.open"
      :group-title="groupTitle(editor.group)"
      :entry="editor.entry"
      :capabilities="capabilities"
      :global-socks5="globalSocks5"
      :proxy-switch="settingsProxy"
      @close="editor.open = false"
      @save="onSave"
    />
  </section>
</template>
