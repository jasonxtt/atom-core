<script setup lang="ts">
import SettingsTabs from '../components/SettingsTabs.vue'
import UpdateCard from '../components/UpdateCard.vue'
import { maintenance } from '../composables/maintenance'
import { backendName, backendVersion, status } from '../composables/status'
</script>

<template>
  <SettingsTabs />
  <UpdateCard />
  <section class="card grid" style="gap: 12px">
    <h2>版本</h2>
    <div class="kv">
      <span>Atom</span><span class="mono">{{ maintenance?.version ?? '—' }}</span>
      <span>AtomDNS</span><span class="mono">{{ status?.atomdns.version ?? '—' }}</span>
      <span>{{ backendName }}</span><span class="mono">{{ backendVersion || '—' }}</span>
    </div>
  </section>
</template>
