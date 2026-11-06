<script setup>
import { defineAsyncComponent } from 'vue'
const GlassSection = import.meta.env.VITE_UI_VARIANT === 'glass'
  ? defineAsyncComponent(() => import('./SystemGlassSection.vue')) : null
import SystemAuditSection from './SystemAuditSection.vue'
import SystemServiceSection from './SystemServiceSection.vue'
import SystemUiSection from './SystemUiSection.vue'
import SystemUpdateSection from './SystemUpdateSection.vue'
</script>

<template>
  <div class="rt-settings-page">
    <SystemUpdateSection />
    <SystemAuditSection />
    <SystemUiSection />
    <GlassSection v-if="GlassSection" />
    <SystemServiceSection />
  </div>
</template>
