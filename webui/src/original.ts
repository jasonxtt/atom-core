// The original judgement (design 3.1, layer 3): what AtomDNS does with an A/AAAA query no rule
// matched, in the order of sequence_6666 (config_custom.yaml), process_listed.yaml and
// process_v4/v6.yaml. No imports, so `npm test` runs it directly.

export interface DnsState {
  core_mode?: 'compat' | 'safe'
  block_empty?: boolean
  learning?: { enabled?: boolean; remember_direct?: boolean; remember_proxy?: boolean; no_v4?: boolean; no_v6?: boolean }
}

export interface Branch {
  key: string
  name: string
  /** The page the branch is set on. */
  to: string
  result: string[]
  off: boolean
}

const LEARNING = '/dns/settings?at=learning'

/** `finalName` is the proxy branches' outbound (Final). */
export function originalBranches(dns: DnsState, finalName: string): Branch[] {
  const learn = dns.learning ?? {}
  // A category is used only while the master switch is on too.
  const on = (key: 'remember_direct' | 'remember_proxy' | 'no_v4' | 'no_v6') => !!learn.enabled && !!learn[key]
  const proxy = `FakeIP · 代理 · ${finalName}`
  const safe = dns.core_mode === 'safe'
  const empty = [on('no_v4') ? '无 V4' : '', on('no_v6') ? '无 V6' : ''].filter(Boolean)
  return [
    { key: 'empty', name: `学到的${(empty.length ? empty : ['无 V4', '无 V6']).join(' / ')}`, to: LEARNING, result: ['空应答'], off: !dns.block_empty || !empty.length },
    { key: 'geosite_no_cn', name: 'geosite_no_cn', to: '/rules/sets?set=geosite_no_cn', result: [proxy], off: false },
    { key: 'geosite_cn', name: 'geosite_cn', to: '/rules/sets?set=geosite_cn', result: ['直连', '国内 DNS'], off: false },
    { key: 'remember_proxy', name: '记忆代理', to: LEARNING, result: [proxy], off: !on('remember_proxy') },
    { key: 'remember_direct', name: '记忆直连', to: LEARNING, result: ['直连', safe ? '国外 DNS' : '国内 DNS'], off: !on('remember_direct') },
    {
      key: 'rest',
      name: `其余 · ${safe ? '安全模式' : '兼容模式'}`,
      to: '/dns/settings?at=mode',
      result: [
        `${safe ? '国外' : '国内'} DNS 探测`,
        '国内 IP / direct_ip → 直连',
        `其他 IP → ${proxy}`,
        '无 IP → 不给地址',
        // Probing learns direct, proxy, and (AAAA) no-IPv6; no-IPv4 is learned by requery only.
        on('remember_direct') || on('remember_proxy') || on('no_v6') ? '学习' : '不学习'
      ],
      off: false
    }
  ]
}
