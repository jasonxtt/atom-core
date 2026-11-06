import { reactive } from 'vue'

const KEY = 'atomdns-bl-appearance-v1'
const defaults = { mode: 'none', image: '', url: '', lightColor: '#f8fafc', darkColor: '#0f172a', opacity: 0.9, blur: 10, text: '', accent: '' }
export const appearance = reactive({ ...defaults })
export function normalizeAppearance(raw = {}) {
  const color = (value, fallback) => /^#[0-9a-f]{6}$/i.test(value || '') ? value : fallback
  const number = (value, max, fallback) => Number.isFinite(Number(value)) ? Math.max(0, Math.min(max, Number(value))) : fallback
  return {
    mode: ['none', 'upload', 'url', 'color'].includes(raw.mode) ? raw.mode : 'none',
    image: /^data:image\/(png|jpeg|webp|gif);base64,/.test(raw.image || '') ? raw.image : '',
    url: /^https?:\/\//i.test(raw.url || '') ? raw.url : '',
    lightColor: color(raw.lightColor, defaults.lightColor), darkColor: color(raw.darkColor, defaults.darkColor),
    opacity: number(raw.opacity ?? .9, 1, .9), blur: number(raw.blur ?? 10, 40, 10),
    text: color(raw.text, ''), accent: color(raw.accent, '')
  }
}
export function applyAppearance() {
  const a = normalizeAppearance(appearance)
  const style = document.documentElement.style
  const image = a.mode === 'upload' ? a.image : a.mode === 'url' ? a.url : ''
  style.setProperty('--page-bg-image', image ? `url(${JSON.stringify(image)})` : 'none')
  style.setProperty('--bl-light-bg', a.mode === 'color' ? a.lightColor : 'transparent')
  style.setProperty('--bl-dark-bg', a.mode === 'color' ? a.darkColor : 'transparent')
  style.setProperty('--panel-glass-opacity', a.opacity)
  style.setProperty('--panel-glass-blur', `${a.blur}px`)
  if (a.accent) {
    const rgb = [1, 3, 5].map(offset => parseInt(a.accent.slice(offset, offset + 2), 16)).join(', ')
    style.setProperty('--brand-rgb', rgb)
  } else style.removeProperty('--brand-rgb')
  for (const [key, value] of [['--ink-0', a.text], ['--rp-text', a.text], ['--brand', a.accent], ['--rp-pine', a.accent]]) {
    if (value) style.setProperty(key, value)
    else style.removeProperty(key)
  }
}
export function saveAppearance() {
  const next = normalizeAppearance(appearance)
  // Persist before reporting success; quota/private-mode errors are shown by the panel.
  localStorage.setItem(KEY, JSON.stringify(next))
  Object.assign(appearance, next)
  applyAppearance()
}
export function resetAppearance() {
  localStorage.removeItem(KEY)
  Object.assign(appearance, defaults)
  applyAppearance()
}
export function initAppearance() {
  try { Object.assign(appearance, normalizeAppearance(JSON.parse(localStorage.getItem(KEY) || '{}'))) } catch { /* use defaults if storage is unavailable */ }
  applyAppearance()
}
