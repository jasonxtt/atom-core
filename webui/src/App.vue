<script setup lang="ts">
import BrandLogo from './components/BrandLogo.vue'
import { computed, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { LogOut, Menu, Monitor, Moon, Sun, X } from '@lucide/vue'
import { navItems } from './nav'
import { health, refreshStatus } from './composables/status'
import { maintenance, refreshMaintenance } from './composables/maintenance'
import { setTheme, theme, themeLabels } from './composables/theme'
import { dismiss, toasts } from './composables/toast'
import { usePoll } from './composables/poll'
import { signedOut } from './api/client'
import { auth, loadAuth, logout } from './composables/auth'
import LoginPage from './pages/LoginPage.vue'

const route = useRoute()
const drawer = ref(false)
const title = computed(() => String(route.meta.title ?? ''))
watch(() => route.fullPath, () => (drawer.value = false))

const active = (path: string) => (path === '/' ? route.path === '/' : route.path === path || route.path.startsWith(`${path}/`))
const nextTheme = { system: 'light', light: 'dark', dark: 'system' } as const
const themeIcons = { system: Monitor, light: Sun, dark: Moon } as const

// The shell waits for the login state; an unreadable one shows the shell (its pages show the failure).
const ready = ref(false)
const needLogin = computed(() => signedOut.value || (auth.value?.enabled === true && !auth.value.authenticated))

loadAuth()
  .catch(() => {})
  .finally(() => {
    ready.value = true
    if (!needLogin.value) {
      refreshStatus().catch(() => {})
      void refreshMaintenance()
    }
  })

usePoll(async () => {
  if (!ready.value) return
  // on the login page: the login may have been turned off from elsewhere; the page is left then
  if (needLogin.value) await loadAuth().catch(() => {})
  else await Promise.allSettled([refreshStatus(), refreshMaintenance()])
}, 5000)

</script>

<template>
  <LoginPage v-if="ready && needLogin" />
  <div v-else-if="ready" class="shell">
    <aside class="side" :class="{ open: drawer }">
      <div class="brand"><BrandLogo /></div>
      <RouterLink v-for="item in navItems" :key="item.path" :to="item.path" class="nav" :class="{ on: active(item.path) }">
        <component :is="item.icon" :size="18" :stroke-width="1.75" />{{ item.label }}
      </RouterLink>
      <div v-if="maintenance" class="foot">Atom v{{ maintenance.version }}</div>
    </aside>
    <div v-if="drawer" class="mask drawer-mask" @click="drawer = false"></div>

    <div class="main">
      <div class="top">
        <button class="ico burger" aria-label="打开菜单" @click="drawer = true">
          <Menu :size="16" :stroke-width="1.8" />
        </button>
        <h1>{{ title }}</h1>
        <span class="pill" :class="health.kind"><span class="dot"></span>{{ health.text }}</span>
        <span class="sp"></span>
        <div id="top-actions" class="row"></div>
        <button class="ico" :aria-label="`主题：${themeLabels[theme]}`" :title="`主题：${themeLabels[theme]}`" @click="setTheme(nextTheme[theme])">
          <component :is="themeIcons[theme]" :size="16" :stroke-width="1.8" />
        </button>
        <button v-if="auth?.enabled" class="ico" aria-label="退出登录" title="退出登录" @click="logout().catch(() => {})">
          <LogOut :size="16" :stroke-width="1.8" />
        </button>
      </div>
      <div class="content">
        <RouterView />
      </div>
    </div>
  </div>

  <div class="toasts">
    <div v-for="item in toasts" :key="item.id" class="toast" :class="item.kind">
      <div class="tx">{{ item.text }}</div>
      <button class="ico" aria-label="关闭" @click="dismiss(item.id)">
        <X :size="14" :stroke-width="2" />
      </button>
    </div>
  </div>
</template>
