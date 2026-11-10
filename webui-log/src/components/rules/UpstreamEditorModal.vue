<script setup>
import { computed, reactive } from 'vue'
import { nativeUpstreamProtocol, nativeUpstreamProtocolFields, normalizeProtocol } from '../../api/nativeManagement'
import { nativeProxyFlag, protocolUsesProxy } from '../../utils/nativeSettings'
import { setError } from '../../utils/notice'
import AppIcon from '../AppIcon.vue'

// Add or edit one upstream. Only what the runtime supports is offered; a record that
// carries anything else is read-only in the list and never reaches this dialog.
const props = defineProps({
  groupTitle: { type: String, required: true },
  // The entry being edited (null for a new one).
  entry: { type: Object, default: null },
  capabilities: { type: Object, default: null },
  globalSocks5: { type: String, default: '' },
  proxySwitch: { type: Boolean, default: false }
})
const emit = defineEmits(['close', 'save'])

const PROTOCOLS = [
  { value: 'udp', label: 'UDP' },
  { value: 'tcp', label: 'TCP' },
  { value: 'tls', label: 'DoT (TLS)' },
  { value: 'https', label: 'DoH (HTTPS)' },
  { value: 'quic', label: 'DoQ (QUIC)' }
]

const supported = computed(() => new Set((props.capabilities?.upstream_protocols || []).map(normalizeProtocol)))
const protocols = computed(() => PROTOCOLS.filter((item) => supported.value.has(item.value)))
const entry = props.entry || {}
const entryProtocol = nativeUpstreamProtocol(entry)
const form = reactive({
  tag: String(entry.tag || ''),
  protocol: entryProtocol === 'h3' ? 'https' : entryProtocol || protocols.value[0]?.value || '',
  http3: entryProtocol === 'h3',
  addr: String(entry.addr || ''),
  dial_addr: String(entry.dial_addr || ''),
  use_socks_proxy: Boolean(entry.use_socks_proxy),
  insecure_skip_verify: Boolean(entry.insecure_skip_verify),
  bootstrap: String(entry.bootstrap || ''),
  bootstrap_version: Number(entry.bootstrap_version || 0),
  upstream_query_timeout: Number(entry.upstream_query_timeout || 0)
})
const showHttp3 = computed(() => form.protocol === 'https' && supported.value.has('h3'))
const useHttp3 = computed(() => showHttp3.value && (form.http3 || form.addr.trimStart().startsWith('h3://')))
const effectiveProtocol = computed(() => useHttp3.value ? 'h3' : form.protocol)
const showProxy = computed(() => props.proxySwitch && protocolUsesProxy(effectiveProtocol.value))
const showTls = computed(() => ['tls', 'https', 'quic'].includes(form.protocol))

function setHttp3(enabled) {
  form.http3 = enabled
  if (!enabled) {
    // Explicitly turning HTTP/3 off also clears the scheme that forces it.
    form.addr = form.addr.replace(/^(\s*)h3:\/\//, '$1https://')
  }
}

function save() {
  const tag = form.tag.trim()
  if (!tag) return setError('上游标识不能为空')
  if (!protocols.value.some((item) => item.value === form.protocol)) return setError('所选协议当前不支持')
  const addr = form.addr.trim()
  if (!addr) return setError('上游地址不能为空')
  emit('save', {
    tag,
    ...nativeUpstreamProtocolFields(effectiveProtocol.value, addr),
    dial_addr: form.dial_addr.trim(),
    bootstrap: form.bootstrap.trim(),
    bootstrap_version: Number(form.bootstrap_version) || 0,
    upstream_query_timeout: Math.max(0, Math.trunc(Number(form.upstream_query_timeout) || 0)),
    insecure_skip_verify: showTls.value ? Boolean(form.insecure_skip_verify) : false,
    ...(props.proxySwitch ? { use_socks_proxy: nativeProxyFlag(effectiveProtocol.value, form.use_socks_proxy) } : {})
  })
}
</script>

<template>
  <Teleport to="body">
    <div class="modal-mask modal-mask-center">
      <section class="panel form-modal-card" role="dialog" :aria-label="entry ? '编辑上游' : '添加上游'">
        <header class="panel-header">
          <h3>{{ entry ? '编辑上游' : '添加上游' }}</h3>
          <button class="rt-row-icon" type="button" aria-label="关闭" title="关闭" @click="emit('close')"><AppIcon name="x" :size="18" /></button>
        </header>
        <div class="form-grid">
          <label>所属组</label>
          <input :value="groupTitle" disabled />
          <label>标识</label>
          <input v-model="form.tag" placeholder="例如 example_dns_1" />
          <label>协议</label>
          <select v-model="form.protocol">
            <option v-for="item in protocols" :key="item.value" :value="item.value">{{ item.label }}</option>
          </select>
          <template v-if="showHttp3">
            <label for="upstream-http3">使用 HTTP/3</label>
            <div>
              <label class="switch-inline"><input id="upstream-http3" type="checkbox" :checked="useHttp3" @change="setHttp3($event.target.checked)" /><span>{{ useHttp3 ? '开启' : '关闭' }}</span></label>
              <small class="muted">HTTP/3 通过 UDP 直连。</small>
            </div>
          </template>
          <label>地址</label>
          <input v-model="form.addr" placeholder="例如 https://dns.example/dns-query 或 192.0.2.1" />
          <label>拨号地址</label>
          <input v-model="form.dial_addr" placeholder="可选，填 IP 可省去域名解析" />
          <template v-if="showProxy">
            <label>使用 SOCKS5 代理</label>
            <div>
              <label class="switch-inline"><input v-model="form.use_socks_proxy" type="checkbox" /><span>{{ form.use_socks_proxy ? '开启' : '关闭' }}</span></label>
              <small class="muted" data-native-proxy-hint>使用“上游设置 › 代理与 ECS”里的 SOCKS5；{{ globalSocks5 ? '当前已设置' : '当前没有设置代理地址，开启后仍直连' }}。</small>
            </div>
          </template>
          <template v-if="showTls">
            <label>跳过证书校验</label>
            <label class="switch-inline"><input v-model="form.insecure_skip_verify" type="checkbox" /><span>{{ form.insecure_skip_verify ? '开启' : '关闭' }}</span></label>
          </template>
          <label>引导 DNS</label>
          <input v-model="form.bootstrap" placeholder="可选，解析上游域名用的 DNS" />
          <label>引导协议版本</label>
          <select v-model.number="form.bootstrap_version">
            <option :value="0">自动</option>
            <option :value="4">IPv4</option>
            <option :value="6">IPv6</option>
          </select>
          <label>查询超时（毫秒）</label>
          <input v-model.number="form.upstream_query_timeout" type="number" min="0" placeholder="0 表示默认" />
        </div>
        <div class="actions">
          <button class="btn secondary" type="button" @click="emit('close')">取消</button>
          <button class="btn primary" type="button" @click="save">保存</button>
        </div>
      </section>
    </div>
  </Teleport>
</template>
