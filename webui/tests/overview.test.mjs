// Overview traffic breakdown, bucketing, cache freshness, and right-aligned sparkline tests.
import test from 'node:test'
import assert from 'node:assert/strict'

import {
  aggregateTraffic,
  appendTrafficSample,
  isCacheFresh,
  niceTrafficCeiling
} from '../src/overviewHelpers.ts'
import { sparkArea, sparkCoords, sparkLine } from '../src/composables/spark.ts'

const names = new Map([
  ['g-default', '默认代理'],
  ['g-stream', '流媒体'],
  ['n-hk', '香港 01'],
  ['n-sg', '新加坡 02'],
  ['direct', '直连'],
  ['block', '拒绝']
])
const nameOf = (id) => (id ? (names.get(id) ?? id) : '—')

test('aggregateTraffic ranks active connections by live rate and computes proxy/direct split', () => {
  const conns = [
    { host: 'youtube.com', ip: '1.1.1.1', src: '10.0.0.25', network: 'tcp', chain: ['g-default', 'n-hk'], download: 5000, upload: 500, dlRate: 800, ulRate: 100 },
    { host: 'netflix.com', ip: '2.2.2.2', src: '10.0.0.42', network: 'udp', chain: ['g-stream', 'n-sg'], download: 2000, upload: 200, dlRate: 200, ulRate: 50 },
    { host: 'bilibili.com', ip: '3.3.3.3', src: '10.0.0.25', network: 'tcp', chain: ['direct'], download: 9000, upload: 100, dlRate: 100, ulRate: 0 }
  ]

  const byGroup = aggregateTraffic(conns, 'group', nameOf)
  assert.equal(byGroup.byRate, true)
  assert.equal(byGroup.clients, 2)
  assert.equal(byGroup.tcp, 2)
  assert.equal(byGroup.udp, 1)
  assert.equal(byGroup.proxyShare, 92)
  assert.equal(byGroup.directShare, 8)
  assert.equal(byGroup.items.length, 3)
  assert.equal(byGroup.items[0].name, '默认代理')
  assert.equal(byGroup.items[0].sub, '→ 香港 01')
  assert.equal(byGroup.items[0].rate, 900)
  assert.equal(byGroup.items[2].name, '直连')
  assert.equal(byGroup.items[2].sub, '国内直连')

  const byClient = aggregateTraffic(conns, 'client', nameOf)
  assert.equal(byClient.items[0].name, '10.0.0.25')
  assert.equal(byClient.items[0].sub, '2 连接')
  assert.equal(byClient.items[0].rate, 1000)

  const byHost = aggregateTraffic(conns, 'host', nameOf)
  assert.equal(byHost.items[0].name, 'youtube.com')
  assert.equal(byHost.items[0].sub, '默认代理 · 1 连接')
})

test('aggregateTraffic falls back to cumulative totals when live rates are zero', () => {
  const conns = [
    { host: 'a.example', ip: '1.1.1.1', src: '10.0.0.2', network: 'tcp', chain: ['g-default', 'n-hk'], download: 100, upload: 50, dlRate: 0, ulRate: 0 },
    { host: 'b.example', ip: '2.2.2.2', src: '10.0.0.3', network: 'tcp', chain: ['direct'], download: 400, upload: 100, dlRate: 0, ulRate: 0 }
  ]
  const summary = aggregateTraffic(conns, 'group', nameOf)
  assert.equal(summary.byRate, false)
  assert.equal(summary.items[0].name, '直连')
  assert.equal(summary.items[0].total, 500)
  assert.equal(summary.directShare, 77)
  assert.equal(summary.proxyShare, 23)
})

test('aggregateTraffic classifies Mihomo traffic by its final outbound and keeps the outer group', () => {
  const conn = { host: 'example.com', ip: '', src: '', network: 'tcp', download: 100, upload: 0, dlRate: 10, ulRate: 0 }
  const summary = aggregateTraffic([
    { ...conn, chain: ['DIRECT'] },
    { ...conn, chain: ['g-default', 'DIRECT'] },
    { ...conn, chain: ['g-default', 'n-hk'] },
    { ...conn, chain: ['g-default', 'REJECT'] }
  ], 'group', nameOf)

  assert.equal(summary.directShare, 67)
  assert.equal(summary.proxyShare, 33)
  assert.deepEqual(summary.items.map(({ key, count }) => [key, count]), [['g-default', 3], ['direct', 1]])
})

test('appendTrafficSample updates current bucket in place and caps length', () => {
  let series = []
  series = appendTrafficSample(series, { ts: 100_100, down: 100, up: 10 }, 2_000, 3)
  series = appendTrafficSample(series, { ts: 101_500, down: 250, up: 25 }, 2_000, 3)
  assert.equal(series.length, 1)
  assert.deepEqual(series[0], { ts: 100_000, down: 250, up: 25 })

  series = appendTrafficSample(series, { ts: 102_000, down: 300, up: 30 }, 2_000, 3)
  series = appendTrafficSample(series, { ts: 104_000, down: 400, up: 40 }, 2_000, 3)
  series = appendTrafficSample(series, { ts: 106_000, down: 500, up: 50 }, 2_000, 3)
  assert.equal(series.length, 3)
  assert.equal(series[0].ts, 102_000)
  assert.equal(series[2].ts, 106_000)
})

test('niceTrafficCeiling applies minimum floor and clean rounding', () => {
  assert.equal(niceTrafficCeiling(0), 128 * 1024)
  assert.ok(niceTrafficCeiling(10 * 1024 * 1024) >= 11.8 * 1024 * 1024)
})

test('isCacheFresh validates timestamp bounds and TTL', () => {
  assert.equal(isCacheFresh(10_000, 15_000, 10_000), true)
  assert.equal(isCacheFresh(10_000, 25_000, 10_000), false)
  assert.equal(isCacheFresh(30_000, 25_000, 10_000), false)
  assert.equal(isCacheFresh(null, 25_000, 10_000), false)
})

test('sparkline renders single-point segments and right-aligned fixed slots', () => {
  assert.equal(sparkLine([], 100), '')
  assert.equal(sparkArea([], 100), '')

  // Single point draws a visible horizontal segment on the right edge (not an invisible point)
  const one = sparkCoords([50], 100, 260, 38, 60)
  assert.equal(one.length, 2)
  assert.ok(one[0][0] < one[1][0])
  assert.equal(one[1][0], 260)
  assert.equal(one[0][1], one[1][1])

  // Two points inside 60 slots right-align near x = 260 instead of stretching across 0..260
  const two = sparkCoords([20, 40], 100, 260, 38, 60)
  assert.equal(two.length, 2)
  assert.ok(two[0][0] > 250)
  assert.equal(two[1][0], 260)
  assert.ok(sparkArea([20, 40], 100, 260, 38, 60).startsWith(`${two[0][0].toFixed(1)},38`))
})
