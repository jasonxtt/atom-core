// The rule dry run's result (`POST rules/dryrun`) in short words. No imports, so `npm test`
// runs it directly.

export interface ChainLink {
  id: string
  name: string
  kind: string
}

export interface Conclusion {
  kind: 'direct' | 'proxy' | 'block' | 'empty' | 'fail'
  via: string
  detail?: string | null
  rcode?: string
  directive?: string
}

export const KIND_LABEL: Record<Conclusion['kind'], string> = {
  direct: '直连',
  proxy: '代理',
  block: '屏蔽',
  empty: '空应答',
  fail: '失败'
}

/** The outbound and each group's current member, to the node (Final by its UI name). */
export function chainNames(chain: ChainLink[], finalName: string): string[] {
  return chain.map((link) => (link.kind === 'final' ? finalName : link.name))
}

/** What decided: the rule, the rewrite, a fixed step or an original branch. */
export function viaLabel(via: string): string {
  const labels: Record<string, string> = {
    rule: '规则',
    rewrite: '重写',
    block_aaaa: 'IPv6 屏蔽',
    prefer_v4: 'IPv4 优先',
    empty: '学到的无 V4 / 无 V6',
    geosite_no_cn: 'geosite 非国内',
    geosite_cn: 'geosite 国内',
    remember_proxy: '记忆代理',
    remember_direct: '记忆直连',
    rest: '探测'
  }
  return labels[via] ?? via
}

/** The directive in words: `SET g` → the group's name, `CLEAR` → Final. */
export function directiveText(directive: string | null | undefined, groupName: (id: string) => string): string {
  if (!directive) return '—'
  if (directive === 'CLEAR') return 'CLEAR'
  return `SET ${groupName(directive.replace(/^SET /, ''))}`
}
