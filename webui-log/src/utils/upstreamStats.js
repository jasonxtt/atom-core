const BUILTIN_GROUP_DEFS = [
  { key: 'domestic', title: '国内直连上游', shortTitle: '国内组', tone: 'domestic' },
  { key: 'nocnfake', title: '国外 FakeIP 上游', shortTitle: 'FakeIP组', tone: 'foreign-fake' },
  { key: 'foreign', title: '国外代理上游', shortTitle: '国外组', tone: 'foreign-proxy' },
  { key: 'foreignecs', title: '国外 ECS 上游', shortTitle: 'ECS组', tone: 'foreign-ecs' },
  { key: 'cnfake', title: '国内 FakeIP 上游', shortTitle: '国内FakeIP组', tone: 'domestic-fake' }
]

const PROTOCOL_LABELS = {
  udp: 'UDP',
  tcp: 'TCP',
  tls: 'DoT',
  dot: 'DoT',
  https: 'DoH',
  doh: 'DoH',
  h3: 'DoH (HTTP/3)',
  quic: 'DoQ',
  doq: 'DoQ',
  aliapi: 'AliAPI'
}

function toNumber(value) {
  const number = Number(value)
  return Number.isFinite(number) ? number : 0
}

function clampNonNegative(value) {
  return Math.max(0, toNumber(value))
}

function decodeLabelValue(value) {
  return String(value || '').replace(/\\"/g, '"').replace(/\\\\/g, '\\')
}

function parseLabels(input = '') {
  const labels = {}
  const regex = /([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"])*)"/g
  let match = regex.exec(input)
  while (match !== null) {
    labels[match[1]] = decodeLabelValue(match[2])
    match = regex.exec(input)
  }
  return labels
}

function emptyMetricBucket() {
  return {
    queryTotal: 0,
    errorTotal: 0,
    winnerTotal: 0,
    latencySum: 0,
    latencyCount: 0
  }
}

function ensureBucket(target, key) {
  if (!target[key]) {
    target[key] = emptyMetricBucket()
  }
  return target[key]
}

function assignMetricValue(bucket, field, value) {
  bucket[field] = clampNonNegative(value)
}

function metricRule(metricName) {
  switch (metricName) {
    case 'atomdns_aliapi_query_total':
      return { field: 'queryTotal', groupLabel: 'metrics_tag', tagLabel: 'tag' }
    case 'atomdns_aliapi_error_total':
      return { field: 'errorTotal', groupLabel: 'metrics_tag', tagLabel: 'tag' }
    case 'atomdns_aliapi_upstream_winner_total':
      return { field: 'winnerTotal', groupLabel: 'metrics_tag', tagLabel: 'tag' }
    case 'atomdns_aliapi_response_latency_millisecond_sum':
      return { field: 'latencySum', groupLabel: 'metrics_tag', tagLabel: 'tag' }
    case 'atomdns_aliapi_response_latency_millisecond_count':
      return { field: 'latencyCount', groupLabel: 'metrics_tag', tagLabel: 'tag' }
    default:
      return null
  }
}

export function parseUpstreamStatsMetrics(rawText = '') {
  const buckets = {}
  const lines = String(rawText || '').split('\n')

  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) {
      continue
    }

    const match = trimmed.match(/^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+([0-9.eE+-]+)$/)
    if (!match) {
      continue
    }

    const rule = metricRule(match[1])
    if (!rule) {
      continue
    }

    const labels = parseLabels(match[2] || '')
    const group = String(labels[rule.groupLabel] || '').trim()
    const tag = String(labels[rule.tagLabel] || '').trim()
    if (!group || !tag) {
      continue
    }

    const bucket = ensureBucket(buckets, `${group}|${tag}`)
    assignMetricValue(bucket, rule.field, match[3])
  }

  return buckets
}

export function orderUpstreamGroups(groupKeys = [], specialGroups = []) {
  const keySet = new Set(groupKeys)
  const ordered = []

  BUILTIN_GROUP_DEFS.forEach((def) => {
    if (keySet.has(def.key)) {
      ordered.push(def.key)
      keySet.delete(def.key)
    }
  })

  const specialOrdered = [...(specialGroups || [])]
    .sort((a, b) => Number(a?.slot || 0) - Number(b?.slot || 0))
    .map((item) => String(item?.upstream_plugin_tag || '').trim())
    .filter(Boolean)

  specialOrdered.forEach((key) => {
    if (keySet.has(key)) {
      ordered.push(key)
      keySet.delete(key)
    }
  })

  return [
    ...ordered,
    ...Array.from(keySet).sort((a, b) => a.localeCompare(b, 'zh-CN'))
  ]
}

export function upstreamGroupDisplay(group, specialGroups = []) {
  const builtin = BUILTIN_GROUP_DEFS.find((item) => item.key === group)
  if (builtin) {
    return builtin
  }

  const special = (specialGroups || []).find((item) => item?.upstream_plugin_tag === group)
  if (special?.name) {
    return {
      key: group,
      title: special.name,
      tone: 'special'
    }
  }

  return {
    key: group,
    title: group || '-',
    tone: 'other'
  }
}

export function protocolDisplayLabel(protocol) {
  const normalized = String(protocol || '').trim().toLowerCase()
  return PROTOCOL_LABELS[normalized] || String(protocol || '-').toUpperCase()
}

export function upstreamAddressDisplay(item = {}) {
  const protocol = String(item.protocol || '').trim().toLowerCase()
  if (protocol === 'aliapi') {
    return String(item.server_addr || '-').trim() || '-'
  }
  return String(item.addr || '-').trim() || '-'
}

// `GET /api/v1/upstream/groups` as `tag → { active, inactive_reason, used_when }`; empty (every
// group in use) when the host does not offer it or the request fails.
export async function loadUpstreamGroups(getJSON, capabilities) {
  if (capabilities?.endpoints?.upstream?.groups_get !== true) return {}
  try {
    const list = await getJSON('/api/v1/upstream/groups')
    if (!Array.isArray(list)) return {}
    return Object.fromEntries(list.filter((group) => typeof group?.tag === 'string').map((group) => [group.tag, { active: group.active !== false, inactive_reason: String(group.inactive_reason || ''), used_when: String(group.used_when || '') }]))
  } catch {
    return {}
  }
}

// The reason a change is refused when it would leave a group without an enabled upstream
// (`list` is the group's list after the change); '' when the change is fine. An empty list
// would mean "restore the configuration file's list" to the host, never "delete the last one".
export function lastUpstreamReason(group, list = [], state = null, title = group) {
  if (Array.isArray(list) && list.some((entry) => entry?.enabled)) return ''
  // `used_when` names the switch for groups in use too; older answers only had the reason.
  const usage = String(state?.used_when || '') || String(state?.inactive_reason || '').replace(/^仅在/, '').replace(/时使用$/, '')
  const switchHint = usage ? `这个组只在${usage}时使用；不想用它，关闭该开关即可。` : ''
  return `上游组「${title}」至少要保留一个启用的上游。${switchHint}`
}
