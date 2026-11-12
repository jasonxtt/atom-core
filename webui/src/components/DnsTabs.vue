<script setup lang="ts">
import { useRoute } from 'vue-router'

const route = useRoute()
const tabs = [
  ['/dns', '概览'],
  ['/dns/logs', '日志'],
  ['/dns/upstreams', '上游'],
  ['/dns/settings', '高级设置']
] as const
</script>

<template>
  <nav class="tabs" aria-label="DNS">
    <RouterLink v-for="tab in tabs" :key="tab[0]" :to="tab[0]" :class="{ on: route.path === tab[0] }">{{ tab[1] }}</RouterLink>
  </nav>
</template>
