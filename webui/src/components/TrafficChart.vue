<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { rate } from '../format'
import { niceTrafficCeiling, TRAFFIC_WINDOWS, type TrafficSample, type TrafficWindow } from '../overviewHelpers'

const props = defineProps<{
  series: TrafficSample[]
  window: TrafficWindow
}>()

const SVG_HEIGHT = 184
const PAD_TOP = 16
const PAD_BOTTOM = 24
const PLOT_H = SVG_HEIGHT - PAD_TOP - PAD_BOTTOM

const containerRef = ref<HTMLElement | null>(null)
const svgWidth = ref(720)
let observer: ResizeObserver | null = null

onMounted(() => {
  const el = containerRef.value
  if (!el) return
  const update = () => {
    const w = Math.round(el.clientWidth)
    if (w > 0) svgWidth.value = w
  }
  update()
  observer = new ResizeObserver(update)
  observer.observe(el)
})

onUnmounted(() => {
  observer?.disconnect()
  observer = null
})

const meta = computed(() => TRAFFIC_WINDOWS[props.window])

const ceiling = computed(() => {
  let peak = 0
  for (const point of props.series) {
    if (point.down > peak) peak = point.down
    if (point.up > peak) peak = point.up
  }
  return niceTrafficCeiling(peak)
})

const gridLines = computed(() =>
  [0, 1, 2, 3].map((index) => {
    const ratio = index / 3
    const y = PAD_TOP + PLOT_H * (1 - ratio)
    const label = index === 0 ? '' : rate(ceiling.value * ratio).replace(' ', '')
    return { y, label }
  })
)

const xLabels = computed(() => {
  const labels = meta.value.axisLabels
  const width = svgWidth.value
  return labels.map((text, index) => ({
    text,
    x: (width * index) / Math.max(1, labels.length - 1),
    anchor: index === 0 ? 'start' : index === labels.length - 1 ? 'end' : 'middle'
  }))
})

interface PlotPoint {
  sample: TrafficSample
  x: number
  yDown: number
  yUp: number
}

const plotted = computed<PlotPoint[]>(() => {
  const list = props.series
  if (!list.length) return []
  const width = svgWidth.value
  const max = ceiling.value
  const totalSlots = Math.max(meta.value.slots, list.length)
  const step = width / Math.max(1, totalSlots - 1)
  const offset = totalSlots - list.length
  const yOf = (val: number) => PAD_TOP + PLOT_H - (Math.max(0, Math.min(val, max)) / max) * PLOT_H

  return list.map((sample, index) => ({
    sample,
    x: list.length === 1 ? width : (offset + index) * step,
    yDown: yOf(sample.down),
    yUp: yOf(sample.up)
  }))
})

function buildPaths(getter: (point: PlotPoint) => number): { line: string; area: string } {
  const pts = plotted.value
  if (!pts.length) return { line: '', area: '' }
  const bottom = (PAD_TOP + PLOT_H).toFixed(1)
  if (pts.length === 1) {
    const p = pts[0]
    const x0 = Math.max(0, p.x - Math.max(svgWidth.value / Math.max(1, meta.value.slots - 1), 10))
    const y = getter(p).toFixed(1)
    const line = `M${x0.toFixed(1)},${y} L${p.x.toFixed(1)},${y}`
    return { line, area: `${line} L${p.x.toFixed(1)},${bottom} L${x0.toFixed(1)},${bottom} Z` }
  }
  const line = pts.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(1)},${getter(p).toFixed(1)}`).join(' ')
  const firstX = pts[0].x.toFixed(1)
  const lastX = pts[pts.length - 1].x.toFixed(1)
  return { line, area: `${line} L${lastX},${bottom} L${firstX},${bottom} Z` }
}

const downPath = computed(() => buildPaths((p) => p.yDown))
const upPath = computed(() => buildPaths((p) => p.yUp))

// Hover state
const hoverIndex = ref<number | null>(null)
const hoverPointerX = ref(0)

const hovered = computed(() => (hoverIndex.value !== null ? (plotted.value[hoverIndex.value] ?? null) : null))

function formatClock(tsMs: number): string {
  const dt = new Date(tsMs)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(dt.getHours())}:${pad(dt.getMinutes())}:${pad(dt.getSeconds())}`
}

function onPointerMove(event: PointerEvent) {
  const pts = plotted.value
  const el = containerRef.value
  if (!pts.length || !el) {
    hoverIndex.value = null
    return
  }
  const rect = el.getBoundingClientRect()
  const x = Math.max(0, Math.min(rect.width, event.clientX - rect.left))
  hoverPointerX.value = x
  // Find nearest plotted sample by X coordinate.
  let best = 0
  let bestDist = Infinity
  for (let i = 0; i < pts.length; i++) {
    const dist = Math.abs(pts[i].x - x)
    if (dist < bestDist) {
      bestDist = dist
      best = i
    }
  }
  hoverIndex.value = best
}

function onPointerLeave() {
  hoverIndex.value = null
}

const tooltipStyle = computed(() => {
  const width = svgWidth.value
  const left = hoverPointerX.value > width * 0.62 ? Math.max(8, hoverPointerX.value - 172) : Math.min(width - 164, hoverPointerX.value + 14)
  return { left: `${left}px` }
})
</script>

<template>
  <div ref="containerRef" class="ov-chart-wrap" @pointermove="onPointerMove" @pointerleave="onPointerLeave">
    <svg :viewBox="`0 0 ${svgWidth} ${SVG_HEIGHT}`" class="ov-chart-svg">
      <defs>
        <linearGradient id="ov-grad-down" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="var(--accent)" stop-opacity="0.24" />
          <stop offset="100%" stop-color="var(--accent)" stop-opacity="0.01" />
        </linearGradient>
        <linearGradient id="ov-grad-up" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="var(--ok)" stop-opacity="0.18" />
          <stop offset="100%" stop-color="var(--ok)" stop-opacity="0.01" />
        </linearGradient>
      </defs>

      <!-- Horizontal gridlines -->
      <g stroke="var(--line)" stroke-dasharray="3 4" stroke-width="1">
        <line v-for="(line, i) in gridLines" :key="i" x1="0" :y1="line.y.toFixed(1)" :x2="svgWidth" :y2="line.y.toFixed(1)" />
      </g>

      <!-- Downlink & Uplink series -->
      <path v-if="downPath.area" :d="downPath.area" fill="url(#ov-grad-down)" />
      <path v-if="downPath.line" :d="downPath.line" fill="none" stroke="var(--accent)" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" />
      <path v-if="upPath.area" :d="upPath.area" fill="url(#ov-grad-up)" />
      <path v-if="upPath.line" :d="upPath.line" fill="none" stroke="var(--ok)" stroke-width="1.8" stroke-linejoin="round" stroke-linecap="round" />

      <!-- Inline Y-axis rate labels -->
      <g fill="var(--muted)" font-size="11" class="tnum">
        <text
          v-for="(line, i) in gridLines"
          :key="i"
          v-show="line.label"
          x="2"
          :y="(line.y - 4).toFixed(1)"
          text-anchor="start"
          paint-order="stroke"
          stroke="var(--card)"
          stroke-width="3.5"
          stroke-linejoin="round"
        >
          {{ line.label }}
        </text>
      </g>

      <!-- Hover crosshair -->
      <template v-if="hovered">
        <line
          :x1="hovered.x.toFixed(1)"
          :y1="PAD_TOP"
          :x2="hovered.x.toFixed(1)"
          :y2="PAD_TOP + PLOT_H"
          stroke="var(--muted)"
          stroke-opacity="0.45"
          stroke-dasharray="3 3"
        />
        <circle :cx="hovered.x.toFixed(1)" :cy="hovered.yDown.toFixed(1)" r="4" fill="var(--accent)" stroke="var(--card)" stroke-width="2" />
        <circle :cx="hovered.x.toFixed(1)" :cy="hovered.yUp.toFixed(1)" r="4" fill="var(--ok)" stroke="var(--card)" stroke-width="2" />
      </template>

      <!-- X-axis labels -->
      <g fill="var(--muted)" font-size="11" class="tnum">
        <text v-for="(label, i) in xLabels" :key="i" :x="label.x.toFixed(1)" :y="SVG_HEIGHT - 6" :text-anchor="label.anchor">
          {{ label.text }}
        </text>
      </g>

      <!-- Empty state hint -->
      <text v-if="!plotted.length" :x="(svgWidth / 2).toFixed(1)" :y="(PAD_TOP + PLOT_H / 2 + 4).toFixed(1)" text-anchor="middle" fill="var(--faint)" font-size="12.5">
        等待流量采样…
      </text>
    </svg>

    <div v-if="hovered" class="ov-tooltip" :style="tooltipStyle">
      <div class="t2 tnum">{{ formatClock(hovered.sample.ts) }}</div>
      <div class="ov-tt-row">
        <span class="ov-tt-lbl"><span class="dot" style="color: var(--accent)"></span>下行</span>
        <span class="tnum">{{ rate(hovered.sample.down) }}</span>
      </div>
      <div class="ov-tt-row">
        <span class="ov-tt-lbl"><span class="dot" style="color: var(--ok)"></span>上行</span>
        <span class="tnum">{{ rate(hovered.sample.up) }}</span>
      </div>
    </div>
  </div>
</template>
