<script setup lang="ts">
/*
 * The connection table: sorting, grouping by a column (groups expand), virtual scrolling, a
 * host/IP switch, column settings. Its structure (TanStack Table's sorted, grouped and
 * expanded row models over a TanStack Virtual list with padding rows) follows zashboard's
 * src/components/connections/ConnectionTable.vue, Copyright 2024 Zephyruso, MIT License
 * (webui/licenses/zashboard-MIT.txt).
 */
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import {
  getCoreRowModel,
  getExpandedRowModel,
  getGroupedRowModel,
  getSortedRowModel,
  useVueTable,
  type ColumnDef,
  type ExpandedState,
  type GroupingState,
  type Row,
  type SortingState
} from '@tanstack/vue-table'
import { useVirtualizer } from '@tanstack/vue-virtual'
import { call, client, describe } from '../api/client'
import AppModal from '../components/AppModal.vue'
import { active, closed, failure, restart, sample, totals, type Conn } from '../composables/connections'
import { loadProxy, nameOf } from '../composables/proxy'
import { toast } from '../composables/toast'
import { bytes, duration, rate } from '../format'

// ---- polling ------------------------------------------------------------------------
const paused = ref(false)
let timer: ReturnType<typeof setTimeout> | undefined
let stopped = false
async function tick() {
  if (stopped) return
  if (!paused.value && !document.hidden) await sample()
  if (!stopped) timer = setTimeout(tick, 2000)
}
onMounted(() => {
  restart()
  loadProxy().catch(() => {})
  void tick()
})
onUnmounted(() => {
  stopped = true
  clearTimeout(timer)
})
watch(paused, (value) => {
  if (!value) restart()
})

// ---- view settings (kept in the browser) ------------------------------------------------
function stored<T>(key: string, fallback: T): T {
  try {
    const value = localStorage.getItem(key)
    return value ? (JSON.parse(value) as T) : fallback
  } catch {
    return fallback
  }
}
function keep(key: string, value: unknown) {
  try {
    localStorage.setItem(key, JSON.stringify(value))
  } catch {
    // not remembered; it still holds for this page
  }
}

type ColumnId = 'close' | 'host' | 'network' | 'rule' | 'chain' | 'dlRate' | 'ulRate' | 'download' | 'upload' | 'src' | 'dst' | 'age'
const LABELS: Record<ColumnId, string> = {
  close: '关闭',
  host: '主机',
  network: '类型',
  rule: '规则',
  chain: '出口链',
  dlRate: '↓ 速率',
  ulRate: '↑ 速率',
  download: '下载',
  upload: '上传',
  src: '来源',
  dst: '目标',
  age: '时长'
}
const GROUPABLE: ColumnId[] = ['host', 'network', 'rule', 'chain', 'src']
const shown = reactive<Record<ColumnId, boolean>>(
  stored('atom-conn-columns', { close: true, host: true, network: true, rule: true, chain: true, dlRate: true, ulRate: true, download: true, upload: true, src: true, dst: false, age: true })
)
watch(shown, (value) => keep('atom-conn-columns', value), { deep: true })
const hostMode = ref<'host' | 'ip'>(stored('atom-conn-host', 'host'))
watch(hostMode, (value) => keep('atom-conn-host', value))
const columnMenu = ref(false)

// ---- filters ----------------------------------------------------------------------------
const view = ref<'active' | 'closed'>('active')
const source = ref('')
const search = ref('')
const regex = ref(false)
const sources = computed(() => [...new Set(active.value.map((conn) => conn.src).filter(Boolean))].sort())
const chainText = (conn: Conn) => conn.chain.map(nameOf).join(' › ')
const hostText = (conn: Conn) => (hostMode.value === 'ip' ? conn.ip || conn.host : conn.host || conn.ip)
const searchError = computed(() => {
  if (!regex.value || !search.value) return ''
  try {
    new RegExp(search.value, 'i')
    return ''
  } catch {
    return '正则写法不对'
  }
})
const data = computed(() => {
  const list = view.value === 'active' ? active.value : closed.value
  const text = search.value.trim()
  let test: (value: string) => boolean = () => true
  if (text) {
    if (regex.value) {
      try {
        const pattern = new RegExp(text, 'i')
        test = (value) => pattern.test(value)
      } catch {
        test = () => true
      }
    } else {
      const lower = text.toLowerCase()
      test = (value) => value.toLowerCase().includes(lower)
    }
  }
  return list.filter((conn) => (!source.value || conn.src === source.value) && test([conn.host, conn.ip, conn.rule, chainText(conn), conn.src].join(' ')))
})

// ---- the table --------------------------------------------------------------------------
const now = ref(Date.now())
const clock = setInterval(() => (now.value = Date.now()), 1000)
onUnmounted(() => clearInterval(clock))

const definitions: ColumnDef<Conn>[] = [
  { id: 'close', enableSorting: false },
  { id: 'host', accessorFn: hostText },
  { id: 'network', accessorFn: (conn) => conn.network },
  { id: 'rule', accessorFn: (conn) => conn.rule },
  { id: 'chain', accessorFn: chainText },
  { id: 'dlRate', accessorFn: (conn) => conn.dlRate, aggregationFn: 'sum', sortDescFirst: true },
  { id: 'ulRate', accessorFn: (conn) => conn.ulRate, aggregationFn: 'sum', sortDescFirst: true },
  { id: 'download', accessorFn: (conn) => conn.download, aggregationFn: 'sum', sortDescFirst: true },
  { id: 'upload', accessorFn: (conn) => conn.upload, aggregationFn: 'sum', sortDescFirst: true },
  { id: 'src', accessorFn: (conn) => conn.src },
  { id: 'dst', accessorFn: (conn) => `${conn.ip || conn.host}:${conn.port}` },
  { id: 'age', accessorFn: (conn) => conn.start, sortDescFirst: false }
]
const columns = definitions.map((column) => ({ ...column, enableGrouping: GROUPABLE.includes(column.id as ColumnId) }))

const sorting = ref<SortingState>(stored('atom-conn-sorting', []))
const grouping = ref<GroupingState>(stored('atom-conn-grouping', []))
const expanded = ref<ExpandedState>({})
watch(sorting, (value) => keep('atom-conn-sorting', value))
watch(grouping, (value) => keep('atom-conn-grouping', value))
const update = <T,>(target: { value: T }) => (updater: T | ((old: T) => T)) => {
  target.value = typeof updater === 'function' ? (updater as (old: T) => T)(target.value) : updater
}

const table = useVueTable({
  get data() {
    return data.value
  },
  columns,
  getRowId: (conn) => conn.id,
  // The columns keep their order when grouped (the expand mark stays first).
  groupedColumnMode: false,
  state: {
    get sorting() {
      return sorting.value
    },
    get grouping() {
      return grouping.value
    },
    get expanded() {
      return expanded.value
    },
    get columnVisibility() {
      return { ...shown, close: shown.close && view.value === 'active' }
    }
  },
  onSortingChange: update(sorting),
  onGroupingChange: update(grouping),
  onExpandedChange: update(expanded),
  getCoreRowModel: getCoreRowModel(),
  getSortedRowModel: getSortedRowModel(),
  getGroupedRowModel: getGroupedRowModel(),
  getExpandedRowModel: getExpandedRowModel(),
  autoResetExpanded: false
})
const rows = computed(() => table.getRowModel().rows)
const visible = computed(() => table.getVisibleLeafColumns())

const scroller = ref<HTMLElement | null>(null)
const virtualizer = useVirtualizer(
  computed(() => ({ count: rows.value.length, getScrollElement: () => scroller.value, estimateSize: () => 37, overscan: 20 }))
)
const virtualRows = computed(() => virtualizer.value.getVirtualItems())
const padTop = computed(() => virtualRows.value[0]?.start ?? 0)
const padBottom = computed(() => {
  const lastRow = virtualRows.value[virtualRows.value.length - 1]
  return lastRow ? virtualizer.value.getTotalSize() - lastRow.end : 0
})

function toggleGroup(id: string) {
  grouping.value = grouping.value[0] === id ? [] : [id]
  expanded.value = {}
}

// ---- closing and details ------------------------------------------------------------------
const detail = ref<Conn | null>(null)
const detailText = computed(() => (detail.value ? JSON.stringify(detail.value.raw, null, 2) : ''))
async function closeOne(conn: Conn) {
  try {
    await call(client.DELETE('/connections/{id}', { params: { path: { id: conn.id } } }))
    await sample()
  } catch (error) {
    toast('bad', describe(error))
  }
}
const closingAll = ref(false)
async function closeAll() {
  try {
    await call(client.DELETE('/connections'))
    toast('ok', '已关闭全部连接')
    await sample()
  } catch (error) {
    toast('bad', describe(error))
  } finally {
    closingAll.value = false
  }
}

function clickRow(row: Row<Conn>) {
  if (row.getIsGrouped()) row.toggleExpanded()
  else detail.value = row.original
}
const sortMark = (id: string) => {
  const sorted = table.getColumn(id)?.getIsSorted()
  return sorted === 'asc' ? ' ▲' : sorted === 'desc' ? ' ▼' : ''
}
const groupValue = (row: Row<Conn>) => String(row.groupingValue ?? '')
</script>

<template>
  <div class="card conns">
    <div class="hd">
      <div class="tabs" role="tablist">
        <button type="button" role="tab" :aria-selected="view === 'active'" :class="{ on: view === 'active' }" @click="view = 'active'">活跃 {{ active.length }}</button>
        <button type="button" role="tab" :aria-selected="view === 'closed'" :class="{ on: view === 'closed' }" @click="view = 'closed'">已关闭 {{ closed.length }}</button>
      </div>
      <select v-model="source" class="inp" style="width: auto" aria-label="来源客户端">
        <option value="">全部客户端</option>
        <option v-for="item in sources" :key="item" :value="item">{{ item }}</option>
      </select>
      <input v-model="search" class="inp" style="width: 220px" :placeholder="regex ? '正则，例如 google|youtube' : '搜索主机、IP、规则、出口'" aria-label="搜索连接" autocomplete="off" />
      <label class="row t2" style="gap: 4px"><input v-model="regex" type="checkbox" /> 正则</label>
      <span class="sp"></span>
      <span class="t2 tnum">↓ {{ rate(totals.downRate) }} · ↑ {{ rate(totals.upRate) }}</span>
      <button class="btn" type="button" :aria-pressed="paused" @click="paused = !paused">{{ paused ? '继续' : '暂停' }}</button>
      <button class="btn danger" type="button" :disabled="view === 'closed' || !active.length" @click="closingAll = true">全部关闭</button>
      <div style="position: relative">
        <button class="btn" type="button" :aria-expanded="columnMenu" @click="columnMenu = !columnMenu">列</button>
        <div v-if="columnMenu" class="pop">
          <label v-for="(label, id) in LABELS" :key="id"><input v-model="shown[id]" type="checkbox" /> {{ label }}</label>
        </div>
      </div>
    </div>
    <div v-if="failure" class="err" style="margin-bottom: 8px">{{ failure }}</div>
    <div v-if="searchError" class="err" style="margin-bottom: 8px">{{ searchError }}</div>
    <div ref="scroller" class="tblwrap conn-scroll">
      <table>
        <thead>
          <tr>
            <th
              v-for="column in visible"
              :key="column.id"
              :aria-sort="column.getIsSorted() === 'asc' ? 'ascending' : column.getIsSorted() === 'desc' ? 'descending' : undefined"
            >
              <button v-if="column.getCanSort()" type="button" class="thsort" @click="column.toggleSorting()">
                {{ LABELS[column.id as ColumnId] }}<span style="color: var(--accent)">{{ sortMark(column.id) }}</span>
              </button>
              <template v-else>{{ LABELS[column.id as ColumnId] }}</template>
              <button v-if="column.id === 'host'" type="button" class="thb" :class="{ on: hostMode === 'ip' }" :title="hostMode === 'ip' ? '显示域名' : '显示 IP'" :aria-label="hostMode === 'ip' ? '显示域名' : '显示 IP'" @click.stop="hostMode = hostMode === 'ip' ? 'host' : 'ip'">⇄</button>
              <button v-if="column.getCanGroup()" type="button" class="thb" :class="{ on: column.getIsGrouped() }" :title="column.getIsGrouped() ? '取消分组' : '按此列分组'" :aria-label="column.getIsGrouped() ? '取消分组' : `按${LABELS[column.id as ColumnId]}分组`" @click.stop="toggleGroup(column.id)">
                <svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="6" /><path d="M20 20l-4.5-4.5" /></svg>
              </button>
            </th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="!rows.length"><td :colspan="visible.length" class="t2" style="text-align: center; padding: 24px">—</td></tr>
          <tr v-if="padTop > 0" :style="{ height: `${padTop}px` }"></tr>
          <tr
            v-for="item in virtualRows"
            :key="rows[item.index].id"
            :class="rows[item.index].getIsGrouped() ? 'grp' : ['crow', { child: rows[item.index].depth > 0 }]"
            tabindex="0"
            @click="clickRow(rows[item.index])"
            @keydown.enter="clickRow(rows[item.index])"
          >
            <template v-if="rows[item.index].getIsGrouped()">
              <td v-for="column in visible" :key="column.id">
                <template v-if="column.id === 'close'">{{ rows[item.index].getIsExpanded() ? '▾' : '▸' }}</template>
                <template v-else-if="column.getIsGrouped()">{{ groupValue(rows[item.index]) || '—' }} <span class="t2">({{ rows[item.index].subRows.length }})</span></template>
                <span v-else-if="column.id === 'dlRate' || column.id === 'ulRate'" class="tnum">{{ rate(Number(rows[item.index].getValue(column.id))) }}</span>
                <span v-else-if="column.id === 'download' || column.id === 'upload'" class="tnum">{{ bytes(Number(rows[item.index].getValue(column.id))) }}</span>
              </td>
            </template>
            <template v-else>
              <td v-for="column in visible" :key="column.id">
                <button v-if="column.id === 'close'" type="button" class="ico" style="width: 24px; height: 24px" aria-label="关闭连接" @click.stop="closeOne(rows[item.index].original)">✕</button>
                <span v-else-if="column.id === 'host'" class="mono">{{ hostText(rows[item.index].original) }}</span>
                <span v-else-if="column.id === 'network'" class="tag">{{ rows[item.index].original.network }}</span>
                <span v-else-if="column.id === 'chain'" class="chain"><span v-for="(tag, index) in rows[item.index].original.chain" :key="index">{{ nameOf(tag) }}</span></span>
                <span v-else-if="column.id === 'dlRate'" class="tnum">{{ rate(rows[item.index].original.dlRate) }}</span>
                <span v-else-if="column.id === 'ulRate'" class="tnum">{{ rate(rows[item.index].original.ulRate) }}</span>
                <span v-else-if="column.id === 'download'" class="tnum">{{ bytes(rows[item.index].original.download) }}</span>
                <span v-else-if="column.id === 'upload'" class="tnum">{{ bytes(rows[item.index].original.upload) }}</span>
                <span v-else-if="column.id === 'src'" class="mono t2">{{ rows[item.index].original.src }}</span>
                <span v-else-if="column.id === 'dst'" class="mono t2">{{ rows[item.index].original.ip || rows[item.index].original.host }}:{{ rows[item.index].original.port }}</span>
                <span v-else-if="column.id === 'age'" class="t2">{{ duration(((rows[item.index].original.closedAt ?? now) - rows[item.index].original.start) / 1000) }}</span>
                <span v-else>{{ rows[item.index].getValue(column.id) }}</span>
              </td>
            </template>
          </tr>
          <tr v-if="padBottom > 0" :style="{ height: `${padBottom}px` }"></tr>
        </tbody>
      </table>
    </div>
  </div>

  <AppModal v-if="detail" :title="`连接详情 ${detail.host}`" @close="detail = null">
    <pre class="json">{{ detailText }}</pre>
    <template #footer>
      <button v-if="view === 'active'" class="btn danger" type="button" @click="closeOne(detail); detail = null">关闭连接</button>
      <button class="btn" type="button" @click="detail = null">关闭</button>
    </template>
  </AppModal>
  <AppModal v-if="closingAll" title="关闭全部连接" @close="closingAll = false">
    <div>当前 {{ active.length }} 条连接会全部断开。</div>
    <template #footer>
      <button class="btn" type="button" @click="closingAll = false">取消</button>
      <button class="btn red" type="button" @click="closeAll">全部关闭</button>
    </template>
  </AppModal>
</template>
