<script setup lang="ts">
import { useRoute } from 'vue-router'

const route = useRoute()
</script>

<template>
  <nav class="tabs" aria-label="规则">
    <RouterLink to="/rules" :class="{ on: route.path === '/rules' }">规则</RouterLink>
    <RouterLink to="/rules/sets" :class="{ on: route.path === '/rules/sets' }">规则集</RouterLink>
  </nav>
</template>
