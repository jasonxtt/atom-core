// The rule dry run's wording (src/dryrun.ts).
import test from 'node:test'
import assert from 'node:assert/strict'

import { chainNames, directiveText, viaLabel, KIND_LABEL } from '../src/dryrun.ts'

test('a chain names Final by its UI name and keeps the rest', () => {
  const chain = [
    { id: 'final', name: 'final', kind: 'final' },
    { id: 'g-default', name: '默认代理', kind: 'selector' },
    { id: 'n-1', name: '日本 01', kind: 'node' }
  ]
  assert.deepEqual(chainNames(chain, '兜底分组'), ['兜底分组', '默认代理', '日本 01'])
})

test('directives and what decided', () => {
  const name = (id) => (id === 'g-ai' ? 'AI' : id)
  assert.equal(directiveText('SET g-ai', name), 'SET AI')
  assert.equal(directiveText('CLEAR', name), 'CLEAR')
  assert.equal(directiveText(null, name), '—')
  assert.equal(viaLabel('geosite_cn'), 'geosite 国内')
  assert.equal(viaLabel('rest'), '探测')
  assert.equal(KIND_LABEL.empty, '空应答')
})
