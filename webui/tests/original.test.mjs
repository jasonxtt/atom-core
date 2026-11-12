// The original judgement under the rule list (src/original.ts).
import test from 'node:test'
import assert from 'node:assert/strict'

import { originalBranches } from '../src/original.ts'

const all = { enabled: true, remember_direct: true, remember_proxy: true, no_v4: true, no_v6: true }

test('branches in the configuration order, proxy ones to Final', () => {
  const branches = originalBranches({ core_mode: 'compat', block_empty: true, learning: all }, 'F')
  assert.deepEqual(branches.map((branch) => branch.key), ['empty', 'geosite_no_cn', 'geosite_cn', 'remember_proxy', 'remember_direct', 'rest'])
  assert.ok(branches.every((branch) => !branch.off))
  assert.deepEqual(branches[1].result, ['FakeIP · 代理 · F'])
  assert.deepEqual(branches[3].result, ['FakeIP · 代理 · F'])
  assert.deepEqual(branches[4].result, ['直连', '国内 DNS'])
  assert.deepEqual(branches[5].result, ['国内 DNS 探测', '国内 IP / direct_ip → 直连', '其他 IP → FakeIP · 代理 · F', '无 IP → 不给地址', '学习'])
  assert.equal(branches[0].name, '学到的无 V4 / 无 V6')
})

test('switches and safe mode', () => {
  const branches = originalBranches({ core_mode: 'safe', block_empty: true, learning: { ...all, no_v4: false, remember_proxy: false } }, 'F')
  assert.equal(branches[0].name, '学到的无 V6')
  assert.equal(branches[3].off, true)
  assert.deepEqual(branches[4].result, ['直连', '国外 DNS'])
  assert.equal(branches[5].name, '其余 · 安全模式')
  assert.equal(branches[5].result[0], '国外 DNS 探测')
  const off = originalBranches({ core_mode: 'compat', block_empty: false, learning: { ...all, enabled: false } }, 'F')
  assert.deepEqual(off.map((branch) => branch.off), [true, false, false, true, true, false])
  assert.equal(off[5].result[4], '不学习')
  const v6 = originalBranches({ core_mode: 'compat', block_empty: true, learning: { enabled: true, no_v6: true } }, 'F')
  assert.equal(v6[5].result[4], '学习')
})
