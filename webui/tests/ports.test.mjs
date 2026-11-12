// The rule form's port entries (src/ports.ts).
import test from 'node:test'
import assert from 'node:assert/strict'

import { parsePorts, portsText } from '../src/ports.ts'

test('ports and ranges', () => {
  assert.deepEqual(parsePorts('443\n8000-9000, 22，443\n1000:\n-2000'), { port: [443, 22], port_range: ['8000:9000', '1000:', ':2000'], bad: [] })
  assert.deepEqual(parsePorts('0\n70000\n9-1\n-\nabc').bad, ['0', '70000', '9-1', '-', 'abc'])
  assert.equal(portsText([443], ['8000:9000', '1000:']), '443\n8000-9000\n1000-')
})
