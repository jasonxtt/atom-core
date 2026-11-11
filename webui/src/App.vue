<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { navItems } from './nav'
import { health, refreshStatus, singboxVersion, status } from './composables/status'
import { setTheme, theme, themeLabels } from './composables/theme'
import { dismiss, toasts } from './composables/toast'
import { usePoll } from './composables/poll'

const route = useRoute()
const drawer = ref(false)
const title = computed(() => String(route.meta.title ?? ''))
watch(() => route.fullPath, () => (drawer.value = false))

const active = (path: string) => (path === '/' ? route.path === '/' : route.path === path || route.path.startsWith(`${path}/`))
const nextTheme = { system: 'light', light: 'dark', dark: 'system' } as const

usePoll(refreshStatus, 5000)

const versions = computed(() => {
  const atomdns = status.value?.atomdns.version
  return [atomdns && `atomdns ${atomdns}`, singboxVersion.value && `sing-box ${singboxVersion.value}`].filter(Boolean)
})
</script>

<template>
  <div class="shell">
    <aside class="side" :class="{ open: drawer }">
      <div class="brand"><i>a</i>atom</div>
      <RouterLink v-for="item in navItems" :key="item.path" :to="item.path" class="nav" :class="{ on: active(item.path) }">
        <svg viewBox="0 0 24 24" v-html="item.icon"></svg>{{ item.label }}
      </RouterLink>
      <div class="foot">
        <div v-for="line in versions" :key="String(line)">{{ line }}</div>
      </div>
    </aside>
    <div v-if="drawer" class="mask drawer-mask" @click="drawer = false"></div>

    <div class="main">
      <div class="top">
        <button class="ico burger" aria-label="打开菜单" @click="drawer = true">
          <svg viewBox="0 0 24 24"><path d="M4 7h16M4 12h16M4 17h16" /></svg>
        </button>
        <h1>{{ title }}</h1>
        <span class="pill" :class="health.kind"><span class="dot"></span>{{ health.text }}</span>
        <span class="sp"></span>
        <div id="top-actions" class="row"></div>
        <button class="ico" :aria-label="`主题：${themeLabels[theme]}`" :title="`主题：${themeLabels[theme]}`" @click="setTheme(nextTheme[theme])">
          <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" /><path d="M12 2v2M12 20v2M2 12h2M20 12h2" /></svg>
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
      <button class="ico" aria-label="关闭" @click="dismiss(item.id)">✕</button>
    </div>
  </div>
</template>
