const UPSTREAM_FIELDS = new Set([
  'tag', 'enabled', 'protocol', 'addr', 'dial_addr', 'bootstrap', 'bootstrap_version',
  'upstream_query_timeout', 'insecure_skip_verify', 'idle_timeout', 'enable_pipeline',
  'enable_http3', 'socks5', 'use_socks_proxy', 'so_mark', 'bind_to_device', 'max_conns',
  'account_id', 'access_key_id', 'access_key_secret', 'server_addr', 'ecs_client_ip',
  'ecs_client_mask'
])

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function isHarmless(value) {
  return value == null || value === false || value === 0 || value === ''
}

export function normalizeProtocol(value) {
  const protocol = String(value || '').trim().toLowerCase()
  switch (protocol) {
    case 'dot': return 'tls'
    case 'doh': return 'https'
    case 'doq': return 'quic'
    default: return protocol
  }
}

export function nativeUpstreamProtocol(upstream) {
  const protocol = normalizeProtocol(upstream?.protocol)
  return protocol === 'https' && upstream.enable_http3 === true ? 'h3' : protocol
}

export function nativeUpstreamProtocolFields(protocol, addr) {
  if (protocol === 'h3' && addr.startsWith('https://')) {
    return { protocol: 'https', addr, enable_http3: true }
  }
  return { protocol, addr }
}

function readOnly(reason) {
  return { readOnly: true, reason }
}

export function isNativeUpstreamReadOnly(upstream, capabilities) {
  if (!isObject(upstream)) return readOnly('上游记录格式无法识别')
  if (Object.keys(upstream).some((key) => !UPSTREAM_FIELDS.has(key))) {
    return readOnly('包含原生端不支持的字段，已保留为只读')
  }
  const supported = new Set((capabilities?.upstream_protocols || []).map(normalizeProtocol))
  const protocol = nativeUpstreamProtocol(upstream)
  if (!protocol || !supported.has(protocol)) {
    return readOnly(`协议 ${upstream.protocol || '(未指定)'} 当前不可用，已保留为只读`)
  }
  // A runtime that does not list `socks_proxy` as unsupported carries the
  // proxy switch of an entry (never a literal `socks5` address).
  const proxySwitch = !(capabilities?.unsupported_features || []).includes('socks_proxy')
  const unsupportedOptions = [
    'idle_timeout', 'enable_pipeline', 'socks5',
    ...(protocol === 'h3' ? [] : ['enable_http3']),
    ...(proxySwitch && !['h3', 'quic'].includes(protocol) ? [] : ['use_socks_proxy']),
    'so_mark', 'bind_to_device', 'max_conns', 'account_id', 'access_key_id',
    'access_key_secret', 'server_addr', 'ecs_client_ip', 'ecs_client_mask'
  ]
  for (const key of unsupportedOptions) {
    if (Object.hasOwn(upstream, key) && !isHarmless(upstream[key])) {
      return readOnly(`包含不支持的 ${key} 配置，已保留为只读`)
    }
  }
  return { readOnly: false, reason: '' }
}

export async function loadDiversionCatalogs(entries, getJSON) {
  const settled = await Promise.allSettled(entries.map(async ([type, tag]) => {
    const data = await getJSON(`/plugins/${tag}/config`)
    return { type, tag, rules: Array.isArray(data) ? data : [] }
  }))
  const catalogs = []
  const failures = []
  settled.forEach((result, index) => {
    if (result.status === 'fulfilled') {
      catalogs.push(result.value)
      return
    }
    const [type, tag] = entries[index]
    failures.push({
      type,
      tag,
      status: result.reason?.status,
      error: result.reason instanceof Error ? result.reason.message : String(result.reason)
    })
  })
  return { catalogs, failures }
}

// The configuration serves the online-source API only for the providers it
// declares. A 404 means "not configured here" and is not an error; any other
// failure is reported.
export async function loadNativeOnlineCatalogs(entries, getJSON) {
  const result = await loadDiversionCatalogs(
    entries.map(([type, tag]) => [type, encodeURIComponent(tag)]),
    getJSON
  )
  const decode = (item) => ({ ...item, tag: decodeURIComponent(item.tag) })
  return {
    catalogs: result.catalogs.map(decode),
    failures: result.failures.filter((failure) => failure.status !== 404).map(decode)
  }
}
