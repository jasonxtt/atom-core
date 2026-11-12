<script setup lang="ts">
import { computed } from 'vue'
import AppModal from './AppModal.vue'
import { attempts, CACHE_STATUS, flags, groupOf, logTime, ms, outcomeLabel, QTYPES, supplier, tagLabel, type AuditLog } from '../composables/dnslog'

const props = defineProps<{ log: AuditLog }>()
const emit = defineEmits<{ close: [] }>()

const tries = computed(() => attempts(props.log))
const basic = computed(() => [
  ['时间', logTime(props.log.query_time, true)],
  ['客户端', props.log.client_ip],
  ['域名', props.log.query_name],
  ['类型', props.log.query_type],
  ['Trace ID', props.log.trace_id]
])
const answer = computed(() => [
  ['响应码', props.log.response_code],
  ['标志位', flags(props.log)],
  ['耗时', ms(props.log.duration_ms)],
  ['缓存', CACHE_STATUS[props.log.cache_status ?? ''] ?? '—']
])
const route = computed(() => [
  ['命中的规则', tagLabel(props.log.domain_set || props.log.effective_tag)],
  ['最终上游组', groupOf(props.log.final_upstream)],
  ['实际上游', supplier(props.log)]
])
</script>

<template>
  <AppModal :title="`查询详情 ${log.query_name}`" @close="emit('close')">
    <h4 class="sec">基本</h4>
    <div class="kv">
      <template v-for="item in basic" :key="item[0]"><span class="t2">{{ item[0] }}</span><span class="mono">{{ item[1] }}</span></template>
    </div>
    <h4 class="sec">应答</h4>
    <div class="kv">
      <template v-for="item in answer" :key="item[0]"><span class="t2">{{ item[0] }}</span><span>{{ item[1] }}</span></template>
    </div>
    <div v-if="log.answers.length" class="tblwrap">
      <table>
        <thead><tr><th>类型</th><th>数据</th><th>TTL</th></tr></thead>
        <tbody>
          <tr v-for="(item, index) in log.answers" :key="index">
            <td>{{ item.type }}</td>
            <td class="mono" style="white-space: normal; overflow-wrap: anywhere">{{ item.data }}</td>
            <td class="tnum">{{ item.ttl }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <h4 class="sec">分流与上游</h4>
    <div class="kv">
      <template v-for="item in route" :key="item[0]"><span class="t2">{{ item[0] }}</span><span>{{ item[1] }}</span></template>
    </div>
    <h4 class="sec">上游尝试</h4>
    <div v-if="tries.length" class="tblwrap">
      <table>
        <thead><tr><th>#</th><th>类型</th><th>上游</th><th>地址</th><th>协议</th><th>结果</th></tr></thead>
        <tbody>
          <tr v-for="item in tries" :key="item.ordinal">
            <td class="tnum t2">{{ item.ordinal + 1 }}</td>
            <td>{{ item.qtype ? (QTYPES[item.qtype] ?? item.qtype) : '—' }}</td>
            <td>{{ item.entry }}</td>
            <td class="mono">{{ item.peer || '—' }}</td>
            <td>{{ item.transport?.toUpperCase() || '—' }}</td>
            <td><span class="pill" :class="item.outcome === 'response' ? 'ok' : item.outcome === 'canceled' ? 'idle' : 'bad'">{{ outcomeLabel(item.outcome) }}</span></td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-else class="t2">—</div>
    <template #footer>
      <button class="btn" type="button" @click="emit('close')">关闭</button>
    </template>
  </AppModal>
</template>
