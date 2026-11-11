import { ref } from 'vue'

export type Theme = 'system' | 'light' | 'dark'
const KEY = 'atom-theme'

function stored(): Theme {
  try {
    const value = localStorage.getItem(KEY)
    if (value === 'light' || value === 'dark') return value
  } catch {
    // storage blocked: follow the system
  }
  return 'system'
}

export const theme = ref<Theme>(stored())

function apply(value: Theme) {
  if (value === 'system') document.documentElement.removeAttribute('data-theme')
  else document.documentElement.setAttribute('data-theme', value)
}
apply(theme.value)

export function setTheme(value: Theme) {
  theme.value = value
  apply(value)
  try {
    if (value === 'system') localStorage.removeItem(KEY)
    else localStorage.setItem(KEY, value)
  } catch {
    // not remembered; the choice still holds for this page
  }
}

export const themeLabels: Record<Theme, string> = { system: '跟随系统', light: '浅色', dark: '深色' }
