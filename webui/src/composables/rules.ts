import { computed, ref } from 'vue'
import { call, client, type Schemas } from '../api/client'
import { FINAL, FINAL_NAME, groups } from './proxy'

export type Rule = Schemas['Rule']
export type Match = Schemas['Match']
export type Ruleset = Schemas['Ruleset']
export type Builtin = Schemas['BuiltinRuleset']
export type UpstreamGroup = Schemas['UpstreamGroup']

/** The rule table and the rulesets share one `version` (the rule table's). */
export const rules = ref<Rule[]>([])
export const rulesVersion = ref(0)
export const builtins = ref<Builtin[]>([])
export const rulesets = ref<Ruleset[]>([])
export const upstreamGroups = ref<UpstreamGroup[]>([])

export async function loadRules() {
  const table = await call(client.GET('/rules'))
  rules.value = table.rules
  rulesVersion.value = table.version
}

export async function loadRulesets() {
  const list = (await call(client.GET('/rulesets'))) as (Builtin | Ruleset)[]
  builtins.value = list.filter((item): item is Builtin => item.type === 'builtin')
  rulesets.value = list.filter((item): item is Ruleset => item.type !== 'builtin')
}

export async function loadUpstreams() {
  upstreamGroups.value = (await call(client.GET('/upstreams'))).groups
}

// ---- names ------------------------------------------------------------------

const PROVIDERS: Record<string, string> = { meta: 'MetaCubeX', bm7: 'blackmatrix7' }

/** A ruleset reference's display name: a builtin set, a custom ruleset, a catalog entry. */
export function setName(id: string): string {
  const builtin = builtins.value.find((item) => item.id === id)
  if (builtin) return builtin.name
  const set = rulesets.value.find((item) => item.id === id)
  if (set) return set.name
  const [provider, name] = id.split(':', 2)
  return name && PROVIDERS[provider] ? `${PROVIDERS[provider]} · ${name}` : id
}

export const isCatalogId = (id: string) => /^(meta|bm7):/.test(id)

export function groupName(id: string): string {
  if (id === FINAL) return FINAL_NAME
  return groups.value.find((group) => group.id === id)?.name ?? id
}

export function upstreamName(tag: string | undefined): string {
  if (!tag) return '国内（默认）'
  return upstreamGroups.value.find((group) => group.tag === tag)?.name ?? tag
}

// ---- name entries (atomdns syntax) ------------------------------------------

/** `domain:` is a suffix, `full:` a whole name; a bare name is `domain:`. */
const PREFIXES = { 'domain:': 'suffix', 'full:': 'domain', 'keyword:': 'keyword', 'regexp:': 'regex' } as const
type NameKind = (typeof PREFIXES)[keyof typeof PREFIXES]

export interface ParsedNames {
  fields: Record<NameKind, string[]>
  count: number
  bad: string[]
}

export function parseNames(text: string): ParsedNames {
  const fields: Record<NameKind, string[]> = { suffix: [], domain: [], keyword: [], regex: [] }
  const bad: string[] = []
  let count = 0
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (!line || line.startsWith('#')) continue
    const prefix = (Object.keys(PREFIXES) as (keyof typeof PREFIXES)[]).find((item) => line.startsWith(item))
    const value = prefix ? line.slice(prefix.length).trim() : line
    if (!value || (!prefix && /^[a-z]+:/i.test(line))) {
      bad.push(line)
      continue
    }
    fields[prefix ? PREFIXES[prefix] : 'suffix'].push(value)
    count++
  }
  return { fields, count, bad }
}

export function namesText(match: Match): string {
  const lines: string[] = []
  for (const value of match.suffix ?? []) lines.push(`domain:${value}`)
  for (const value of match.domain ?? []) lines.push(`full:${value}`)
  for (const value of match.keyword ?? []) lines.push(`keyword:${value}`)
  for (const value of match.regex ?? []) lines.push(`regexp:${value}`)
  return lines.join('\n')
}

export const lines = (text: string) =>
  text
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)

// ---- summaries ----------------------------------------------------------------

function some(values: string[], limit = 3): string {
  return values.length > limit ? `${values.slice(0, limit).join('、')} 等 ${values.length} 个` : values.join('、')
}

/** What a rule matches, in one line. */
export function summary(match: Match): string {
  const parts: string[] = []
  const names = [...(match.suffix ?? []), ...(match.domain ?? []), ...(match.keyword ?? []), ...(match.regex ?? [])]
  if (names.length) parts.push(`域名 ${some(names)}`)
  const sets = match.ruleset ?? []
  const ipSets = match.ip_ruleset ?? []
  const both = sets.filter((id) => ipSets.includes(id))
  const namesOnly = sets.filter((id) => !ipSets.includes(id))
  const ipsOnly = ipSets.filter((id) => !sets.includes(id))
  if (namesOnly.length) parts.push(`规则集 ${some(namesOnly.map(setName))}`)
  if (both.length) parts.push(`规则集（全部） ${some(both.map(setName))}`)
  if (ipsOnly.length) parts.push(`规则集（IP） ${some(ipsOnly.map(setName))}`)
  if (match.ip_cidr?.length) parts.push(`目标 IP ${some(match.ip_cidr)}`)
  const head = parts.join(' 或 ')
  if (!match.client?.length) return head
  const clients = `${match.client_invert ? '名单外的客户端' : '客户端'} ${some(match.client)}`
  return head ? `${head}，且${clients}` : clients
}

export function actionLabel(action: Schemas['Action']): string {
  if (action.type === 'proxy') return `代理 → ${groupName(action.group_id)}`
  return action.type === 'direct' ? '直连' : '屏蔽'
}

export const hasNames = (match: Match) =>
  !!(match.domain?.length || match.suffix?.length || match.keyword?.length || match.regex?.length || match.ruleset?.length)

/** The DNS side of a rule (empty for a block rule). */
export function dnsLabel(rule: Pick<Rule, 'action' | 'match' | 'dns' | 'cache'>): string {
  if (rule.action.type === 'block') return ''
  if (rule.action.type === 'proxy') return 'FakeIP'
  // A rule of clients alone meets every name those clients ask.
  if (!hasNames(rule.match) && !rule.match.client?.length) return '不经过 DNS'
  return `${upstreamName(rule.dns)}${rule.cache === false ? ' · 不缓存' : ''}`
}

/** Proxy targets: the node groups and Final. */
export const proxyTargets = computed(() => [...groups.value.map((group) => ({ id: group.id, name: group.name })), { id: FINAL, name: FINAL_NAME }])
