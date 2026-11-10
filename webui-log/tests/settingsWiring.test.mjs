import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'

import { isNativeUpstreamReadOnly, nativeUpstreamProtocol, nativeUpstreamProtocolFields } from '../src/api/nativeManagement.js'
import { requestOperation } from '../src/api/runtimeCapabilities.js'
import {
  isModified,
  nativeProxyFlag,
  protocolUsesProxy,
  settingsBackedProxy,
  settingsSources
} from '../src/utils/nativeSettings.js'

const settingsBacked = {
  kind: 'native',
  upstream_protocols: ['udp', 'tcp', 'dot', 'doh'],
  unsupported_features: ['signed_aliapi', 'quic', 'http3', 'socket_marks', 'bind_to_device', 'positive_idle_timeout', 'enable_pipeline']
}
const managed = { ...settingsBacked, unsupported_features: [...settingsBacked.unsupported_features, 'socks_proxy'] }

test('the proxy switch is carried only by a runtime that does not list socks_proxy as unsupported', () => {
  assert.equal(settingsBackedProxy(settingsBacked), true)
  assert.equal(settingsBackedProxy(managed), false)
  assert.equal(settingsBackedProxy({ kind: 'legacy' }), false)
  assert.equal(settingsBackedProxy(undefined), false)
  assert.equal(settingsBackedProxy({ kind: 'native' }), false, 'no feature list means no claim')
})

test('a proxied entry is editable on a settings-backed runtime, a literal socks5 is not', () => {
  const entry = { tag: 'google', protocol: 'https', enabled: true, addr: 'https://dns.google/dns-query', use_socks_proxy: true }
  assert.deepEqual(isNativeUpstreamReadOnly(entry, settingsBacked), { readOnly: false, reason: '' })
  assert.equal(isNativeUpstreamReadOnly(entry, managed).readOnly, true, 'the managed runtime keeps it read-only')
  assert.equal(isNativeUpstreamReadOnly({ ...entry, socks5: '10.0.0.1:1080' }, settingsBacked).readOnly, true)
  assert.equal(isNativeUpstreamReadOnly({ ...entry, use_socks_proxy: false, so_mark: 3 }, settingsBacked).readOnly, true)
})

test('only protocols that can use a proxy carry a checked switch', () => {
  for (const protocol of ['tcp', 'tls', 'dot', 'https', 'doh', 'HTTPS']) {
    assert.equal(protocolUsesProxy(protocol), true, protocol)
    assert.equal(nativeProxyFlag(protocol, true), true)
    assert.equal(nativeProxyFlag(protocol, false), false)
  }
  for (const protocol of ['udp', 'h3', 'quic', 'doq', 'aliapi', '', undefined]) assert.equal(nativeProxyFlag(protocol, true), false, String(protocol))
})

test('QUIC upstream editing follows runtime capabilities and refuses a proxy', () => {
  const capable = { ...settingsBacked, upstream_protocols: [...settingsBacked.upstream_protocols, 'h3', 'quic'], unsupported_features: [] }
  for (const [entry, protocol] of [
    [{ protocol: 'https', addr: 'https://dns.example/dns-query', enable_http3: true }, 'h3'],
    [{ protocol: 'h3', addr: 'h3://dns.example/dns-query' }, 'h3'],
    [{ protocol: 'doq', addr: 'doq://dns.example' }, 'quic']
  ]) {
    assert.equal(nativeUpstreamProtocol(entry), protocol)
    assert.equal(isNativeUpstreamReadOnly(entry, settingsBacked).readOnly, true)
    assert.equal(isNativeUpstreamReadOnly(entry, capable).readOnly, false)
    assert.equal(isNativeUpstreamReadOnly({ ...entry, use_socks_proxy: true }, capable).readOnly, true)
  }
})

test('the upstream editor preserves explicit schemes and the HTTPS HTTP/3 flag', () => {
  const https = 'https://dns.example/resolve?x=1'
  const h3 = 'h3://dns.example/resolve?x=1'
  assert.deepEqual(nativeUpstreamProtocolFields('h3', https), { protocol: 'https', addr: https, enable_http3: true })
  assert.deepEqual(nativeUpstreamProtocolFields('h3', 'dns.example'), { protocol: 'https', addr: 'dns.example', enable_http3: true })
  assert.deepEqual(nativeUpstreamProtocolFields('h3', h3), { protocol: 'h3', addr: h3 })
  assert.deepEqual(nativeUpstreamProtocolFields('https', h3), { protocol: 'https', addr: h3 })
  assert.deepEqual(nativeUpstreamProtocolFields('https', https), { protocol: 'https', addr: https })
})

test('effective items become the modified marks of the pages', () => {
  const marks = settingsSources({
    items: [
      { object: 'main_proxy', kind: 'socks5_proxy', field: 'addr', value: '10.0.0.1:1080', source: 'settings' },
      { object: 'client_ecs', kind: 'ecs_address', field: 'addr', value: '2408:8888::8', source: 'yaml' },
      { object: 'foreign', kind: 'aliapi', field: 'upstreams', value: 'a=udp://1.1.1.1', source: 'settings' },
      { object: 'domestic', kind: 'aliapi', field: 'upstreams', value: 'b=udp://2.2.2.2', source: 'yaml' },
      { object: 'my_realiplist', kind: 'domain_output', field: 'enabled', value: 'true', source: 'yaml' },
      null
    ]
  })
  assert.deepEqual(marks, { socks5: 'settings', ecs: 'yaml', upstreams: { foreign: 'settings', domestic: 'yaml' } })
  assert.equal(isModified(marks.socks5), true)
  assert.equal(isModified(marks.ecs), false)
  assert.deepEqual(settingsSources(undefined), { socks5: '', ecs: '', upstreams: {} })
  assert.deepEqual(settingsSources({ items: 'x' }), { socks5: '', ecs: '', upstreams: {} })
})

test('the effective-settings read is a plain, ungated request', () => {
  assert.equal(requestOperation('/api/v1/settings/effective', 'GET'), null)
  assert.equal(requestOperation('/api/v1/overrides', 'POST'), 'system.global_overrides')
  assert.equal(requestOperation('/api/v1/upstream/config', 'POST'), 'upstreams.manage')
})

test('the overrides apply at once with a restore per field, and no replacement rules are offered', async () => {
  const source = await readFile(new URL('../src/components/rules/OverridesPanel.vue', import.meta.url), 'utf8')
  // Saves send an empty replacements list, never ask for a restart and can restore a field.
  const save = source.slice(source.indexOf('async function saveOverrides()'), source.indexOf('onMounted('))
  assert.match(save, /replacements: \[\]/)
  assert.doesNotMatch(save, /system\/restart/)
  assert.match(source, /async function restoreOverride\(field\)/)
  assert.match(source, /@click="restoreOverride\('socks5'\)"/)
  assert.match(source, /@click="restoreOverride\('ecs'\)"/)
  assert.doesNotMatch(source, /replacements\.push|addReplacement|NATIVE_REPLACEMENTS_NOTE/, 'no editor or note for replacement rules')
  const page = await readFile(new URL('../src/pages/rules/RulesUpstreamPage.vue', import.meta.url), 'utf8')
  assert.match(page, /<OverridesPanel \/>/)
})

test('the upstream dialog offers the proxy switch only on a settings-backed runtime and never a literal address or an unsupported field', async () => {
  const source = await readFile(new URL('../src/components/rules/UpstreamEditorModal.vue', import.meta.url), 'utf8')
  assert.match(source, /showProxy = computed\(\(\) => props\.proxySwitch && protocolUsesProxy\(effectiveProtocol\.value\)\)/)
  assert.match(source, /nativeProxyFlag\(effectiveProtocol\.value, form\.use_socks_proxy\)/)
  assert.match(source, /showHttp3 = computed\(\(\) => form\.protocol === 'https' && supported\.value\.has\('h3'\)\)/)
  assert.match(source, /@change="setHttp3\(\$event\.target\.checked\)"/)
  assert.doesNotMatch(source, /value: 'h3'/, 'HTTP/3 is a DoH toggle')
  for (const gone of ['idle_timeout', 'bind_to_device', 'so_mark', 'enable_pipeline', 'enable_http3', 'socks5', 'aliapi', 'account_id']) {
    assert.doesNotMatch(source, new RegExp(gone), `${gone} is not offered`)
  }
  const panel = await readFile(new URL('../src/components/rules/UpstreamPanel.vue', import.meta.url), 'utf8')
  assert.match(panel, /plugin_tag: group, upstreams: \[\]/, 'restore default posts an empty list')
  // The table keeps identifier, protocol, address, enabled, latency and the actions.
  const head = panel.slice(panel.indexOf('<thead>'), panel.indexOf('</thead>'))
  assert.deepEqual([...head.matchAll(/<th[^>]*>([^<]+)<\/th>/g)].map((match) => match[1].replace(/\{\{.*?\}\}/g, '').trim()), ['标识', '协议', '地址', '启用', '延迟', '操作'])
  // The old table's group filter, sorting and "hide disabled" (same storage key) stay.
  assert.match(panel, /atomdns-hide-disabled-upstreams/)
  assert.match(panel, /aria-label="按组筛选"/)
  assert.match(panel, /onSort\('tag'\)/)
})
