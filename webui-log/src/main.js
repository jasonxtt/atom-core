import { createApp } from 'vue'
import App from './App.vue'
import { pageComponent } from './pages'
import { createAppRouter } from './router'
import { openConfirm } from './utils/confirm'
import { createThemeController } from './utils/theme'
import { leaveMessage } from './utils/unsaved'
import './style.css'
if (import.meta.env.VITE_UI_VARIANT === 'glass') {
  import('./glass.css')
  import('./utils/glassAppearance').then(({ initAppearance }) => initAppearance())
}

let storage = null
try { storage = window.localStorage } catch { /* blocked storage: the theme follows the system */ }
const theme = createThemeController({ root: document.documentElement, storage, matchMedia: window.matchMedia?.bind(window) })

createApp(App)
  .use(createAppRouter({ pageComponent, confirmLeave: () => openConfirm(leaveMessage(), { title: '有未保存的改动', confirmText: '离开', tone: 'danger' }) }))
  .provide('theme', theme)
  .mount('#app')
