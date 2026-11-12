<script setup lang="ts">
import { reactive, ref } from 'vue'
import AppModal from './AppModal.vue'
import type { Schemas } from '../api/client'

type Upstream = Schemas['Upstream']
/** Edits one upstream locally (the group is saved as a whole); `upstream` absent adds one. */
const props = defineProps<{ group: string; upstream?: Upstream; tags: string[]; withName?: boolean; pending?: boolean }>()
const emit = defineEmits<{ close: []; save: [upstream: Upstream, name: string]; remove: [] }>()

const PROTOCOLS = [
  ['udp', 'UDP'],
  ['tcp', 'TCP'],
  ['tls', 'DoT（tls）'],
  ['https', 'DoH（https）'],
  ['quic', 'DoQ（quic）']
] as const
const PLACEHOLDERS: Record<string, string> = {
  udp: '例如 223.5.5.5 或 223.5.5.5:53',
  tcp: '例如 tcp://223.5.5.5',
  tls: '例如 tls://dns.alidns.com',
  https: '例如 https://dns.alidns.com/dns-query',
  quic: '例如 quic://dns.alidns.com'
}
const source = props.upstream
const ALIASES: Record<string, Upstream['protocol']> = { dot: 'tls', doh: 'https', h3: 'https', doq: 'quic' }
const protocol = ALIASES[source?.protocol ?? ''] ?? source?.protocol ?? 'udp'
const form = reactive({
  name: '',
  tag: source?.tag ?? '',
  protocol,
  addr: source?.addr ?? '',
  dial_addr: source?.dial_addr ?? '',
  timeout: source?.upstream_query_timeout ? String(source.upstream_query_timeout) : '',
  bootstrap: source?.bootstrap ?? '',
  bootstrap_version: source?.bootstrap_version ?? 0,
  use_proxy: !!source?.use_proxy,
  insecure: !!source?.insecure_skip_verify,
  http3: source?.protocol === 'h3' || !!source?.enable_http3 || !!source?.addr?.startsWith('h3://'),
  enabled: source?.enabled !== false
})
const error = ref('')
/** UDP, DoQ and DoH over HTTP/3 cannot go through the proxy. */
const proxyable = () => form.protocol !== 'udp' && form.protocol !== 'quic' && !(form.protocol === 'https' && form.http3)

function submit() {
  if (props.pending) return
  error.value = ''
  const tag = form.tag.trim()
  if (props.withName && !form.name.trim()) return void (error.value = '请填写组名')
  if (!tag) return void (error.value = '请填写名称')
  if (tag !== source?.tag && props.tags.includes(tag)) return void (error.value = `名称「${tag}」已被其他上游使用`)
  if (!form.addr.trim()) return void (error.value = '请填写地址')
  const timeout = form.timeout.trim()
  if (timeout && !/^\d+$/.test(timeout)) return void (error.value = '查询超时应为毫秒数')
  const http3 = form.protocol === 'https' && form.http3
  // `h3://` is written as `https://` with `enable_http3`.
  const addr = form.protocol === 'https' ? form.addr.trim().replace(/^h3:\/\//i, 'https://') : form.addr.trim()
  // Fields this form does not show stay as they were.
  const upstream: Upstream = {
    ...(source ?? {}),
    tag,
    protocol: form.protocol,
    addr,
    enabled: form.enabled,
    use_proxy: proxyable() && form.use_proxy,
    insecure_skip_verify: form.protocol !== 'udp' && form.protocol !== 'tcp' && form.insecure
  }
  if (http3) upstream.enable_http3 = true
  else delete upstream.enable_http3
  const optional = { dial_addr: form.dial_addr.trim(), bootstrap: form.bootstrap.trim() }
  for (const [key, value] of Object.entries(optional)) {
    if (value) (upstream as Record<string, unknown>)[key] = value
    else delete (upstream as Record<string, unknown>)[key]
  }
  if (timeout && Number(timeout) > 0) upstream.upstream_query_timeout = Number(timeout)
  else delete upstream.upstream_query_timeout
  if (form.bootstrap_version) upstream.bootstrap_version = form.bootstrap_version
  else delete upstream.bootstrap_version
  emit('save', upstream, form.name.trim())
}
</script>

<template>
  <AppModal :title="`${withName ? '新建上游组' : upstream ? '编辑上游' : '添加上游'}${group ? ` · ${group}` : ''}`" @close="emit('close')">
    <div v-if="withName" class="field">
      <label for="ugname">组名</label>
      <input id="ugname" v-model="form.name" class="inp" autocomplete="off" />
    </div>
    <div class="grid g2" style="gap: 12px">
      <div class="field">
        <label for="uftag">名称</label>
        <input id="uftag" v-model="form.tag" class="inp mono" placeholder="例如 aliyun-doh" autocomplete="off" />
      </div>
      <div class="field">
        <label for="ufproto">协议</label>
        <select id="ufproto" v-model="form.protocol" class="inp">
          <option v-for="item in PROTOCOLS" :key="item[0]" :value="item[0]">{{ item[1] }}</option>
        </select>
      </div>
    </div>
    <div class="field">
      <label for="ufaddr">地址</label>
      <input id="ufaddr" v-model="form.addr" class="inp mono" :placeholder="PLACEHOLDERS[form.protocol]" autocomplete="off" />
    </div>
    <div class="grid g2" style="gap: 12px">
      <div class="field">
        <label for="ufdial">拨号地址</label>
        <input id="ufdial" v-model="form.dial_addr" class="inp mono" autocomplete="off" />
      </div>
      <div class="field">
        <label for="uftimeout">查询超时（毫秒）</label>
        <input id="uftimeout" v-model="form.timeout" class="inp mono" inputmode="numeric" placeholder="默认" autocomplete="off" />
      </div>
      <div class="field">
        <label for="ufboot">引导 DNS</label>
        <input id="ufboot" v-model="form.bootstrap" class="inp mono" autocomplete="off" />
      </div>
      <div class="field">
        <label for="ufbv">引导协议版本</label>
        <select id="ufbv" v-model.number="form.bootstrap_version" class="inp">
          <option :value="0">自动</option>
          <option :value="4">IPv4</option>
          <option :value="6">IPv6</option>
        </select>
      </div>
    </div>
    <div class="row">
      <div style="flex: 1">走代理</div>
      <button class="sw" type="button" :class="{ on: form.use_proxy && proxyable() }" :disabled="!proxyable()" :aria-pressed="form.use_proxy && proxyable()" aria-label="走代理" @click="form.use_proxy = !form.use_proxy"></button>
    </div>
    <div v-if="form.protocol === 'https'" class="row">
      <div style="flex: 1">HTTP/3</div>
      <button class="sw" type="button" :class="{ on: form.http3 }" :aria-pressed="form.http3" aria-label="HTTP/3" @click="form.http3 = !form.http3"></button>
    </div>
    <div v-if="form.protocol !== 'udp' && form.protocol !== 'tcp'" class="row">
      <div style="flex: 1">跳过证书校验</div>
      <button class="sw" type="button" :class="{ on: form.insecure }" :aria-pressed="form.insecure" aria-label="跳过证书校验" @click="form.insecure = !form.insecure"></button>
    </div>
    <div class="row">
      <div style="flex: 1">启用</div>
      <button class="sw" type="button" :class="{ on: form.enabled }" :aria-pressed="form.enabled" aria-label="启用" @click="form.enabled = !form.enabled"></button>
    </div>
    <div v-if="error" class="err">{{ error }}</div>
    <template #footer>
      <button v-if="upstream" class="btn danger" type="button" style="margin-right: auto" @click="emit('remove')">删除</button>
      <button class="btn" type="button" @click="emit('close')">取消</button>
      <button class="btn pri" type="button" :disabled="pending" @click="submit">{{ withName ? '创建' : '确定' }}</button>
    </template>
  </AppModal>
</template>
