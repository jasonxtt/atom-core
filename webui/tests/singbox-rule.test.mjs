// The rule form's port entries and pasted sing-box headless rules (src/singboxRule.ts).
import test from 'node:test'
import assert from 'node:assert/strict'

import { parseHeadlessRule, parsePorts, portsText, TRANSPORT_WITH_NAMES } from '../src/singboxRule.ts'

test('ports and ranges', () => {
  assert.deepEqual(parsePorts('443\n8000-9000, 22，443\n1000:\n-2000'), { port: [443, 22], port_range: ['8000:9000', '1000:', ':2000'], bad: [] })
  assert.deepEqual(parsePorts('0\n70000\n9-1\n-\nabc').bad, ['0', '70000', '9-1', '-', 'abc'])
  assert.equal(portsText([443], ['8000:9000', '1000:']), '443\n8000-9000\n1000-')
})

test('a headless rule is split into the form fields', () => {
  const result = parseHeadlessRule(
    JSON.stringify({ domain: 'a.example', domain_suffix: ['.b.example', 'c.example'], domain_keyword: 'ads', domain_regex: ['^x\\.'], source_ip_cidr: '192.168.1.0/24' })
  )
  assert.deepEqual(result.fields, {
    domain: ['a.example'],
    suffix: ['b.example', 'c.example'],
    keyword: ['ads'],
    regex: ['^x\\.'],
    ip_cidr: [],
    port: [],
    port_range: [],
    network: [],
    client: ['192.168.1.0/24']
  })
  const ip = parseHeadlessRule('{"ip_cidr": ["91.108.4.0/22"], "port": [443, 443], "port_range": "1000:2000", "network": ["TCP"]}')
  assert.deepEqual(ip.fields.ip_cidr, ['91.108.4.0/22'])
  assert.deepEqual(ip.fields.port, [443])
  assert.deepEqual(ip.fields.port_range, ['1000:2000'])
  assert.deepEqual(ip.fields.network, ['tcp'])
})

test('what the form cannot take is an error, never dropped', () => {
  const error = (text) => parseHeadlessRule(text).error
  assert.match(error('{"domain": "a", "rule_set": "x", "protocol": "tls"}'), /不支持的字段：rule_set、protocol/)
  for (const field of ['process_name', 'invert', 'source_port', 'ip_is_private', 'outbound', 'type']) {
    assert.match(error(JSON.stringify({ [field]: 'x', domain: 'a' })), /不支持的字段/, field)
  }
  assert.match(error('not json'), /不是 JSON/)
  assert.match(error('[{"domain": "a"}]'), /JSON 对象/)
  assert.match(error('{}'), /没有条件/)
  assert.match(error('{"port": "443"}'), /port 的值/)
  assert.match(error('{"port": 0}'), /port 的值/)
  assert.match(error('{"port_range": "1000-2000"}'), /port_range/)
  assert.match(error('{"network": "icmp"}'), /tcp 或 udp/)
  assert.match(error('{"domain": 5}'), /不是字符串/)
  assert.equal(error('{"port": 443, "domain_suffix": "a.example"}'), TRANSPORT_WITH_NAMES)
  assert.equal(error('{"network": "udp", "source_ip_cidr": "10.0.0.1"}'), TRANSPORT_WITH_NAMES)
  assert.match(error('{"ip_cidr": "1.1.1.1", "source_ip_cidr": "10.0.0.1"}'), /客户端/)
})
