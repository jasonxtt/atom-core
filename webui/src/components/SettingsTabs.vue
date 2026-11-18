<script setup lang="ts">
import { useRoute } from 'vue-router'

const route = useRoute()
const tabs = [
  ['/settings/proxy', '代理'],
  ['/settings/network', '网络'],
  ['/settings/panel', '面板'],
  ['/settings/system', '系统']
] as const
</script>

<template>
  <nav class="tabs" aria-label="设置">
    <RouterLink v-for="tab in tabs" :key="tab[0]" :to="tab[0]" :class="{ on: route.path === tab[0] }">{{ tab[1] }}</RouterLink>
  </nav>
</template>
