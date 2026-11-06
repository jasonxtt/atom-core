import test from 'node:test'
import assert from 'node:assert/strict'
import { appearance, normalizeAppearance, applyAppearance, saveAppearance, initAppearance, resetAppearance } from '../src/utils/glassAppearance.js'

test('local glass preferences reject invalid images/colors and bound the controls', () => {
  const a = normalizeAppearance({ mode: 'unknown', image: 'data:image/svg+xml;base64,aaa', url: 'javascript:alert(1)', lightColor: 'red', opacity: -5, blur: 100 })
  assert.equal(a.mode, 'none')
  assert.equal(a.image, '')
  assert.equal(a.url, '')
  assert.equal(a.lightColor, '#f8fafc')
  assert.equal(a.opacity, 0)
  assert.equal(a.blur, 40)
})

test('the accent and all glass variables share the saved settings, including zero alpha', () => {
  const props = new Map()
  globalThis.document = { documentElement: { style: { setProperty: (k, v) => props.set(k, String(v)), removeProperty: k => props.delete(k) } } }
  const defaults = normalizeAppearance()
  Object.assign(appearance, defaults, { opacity: 0, blur: 0, accent: '#123456' })
  applyAppearance()
  assert.equal(props.get('--panel-glass-opacity'), '0')
  assert.equal(props.get('--panel-glass-blur'), '0px')
  assert.equal(props.get('--brand-rgb'), '18, 52, 86')
  assert.equal(props.get('--brand'), '#123456')
  Object.assign(appearance, defaults)
  applyAppearance()
  assert.equal(props.has('--brand-rgb'), false)
  assert.equal(props.has('--brand'), false)
})

test('image and sliders survive a browser-local reload; reset removes the image; quota errors propagate', () => {
  const memory = new Map()
  globalThis.localStorage = { setItem: (k, v) => memory.set(k, v), getItem: k => memory.get(k), removeItem: k => memory.delete(k) }
  Object.assign(appearance, normalizeAppearance({mode: 'upload', image: 'data:image/jpeg;base64,abc', opacity: .65, blur: 18}))
  saveAppearance()
  Object.assign(appearance, normalizeAppearance())
  initAppearance()
  assert.equal(appearance.image, 'data:image/jpeg;base64,abc')
  assert.equal(appearance.opacity, .65)
  assert.equal(appearance.blur, 18)
  resetAppearance()
  assert.equal(memory.size, 0)
  assert.equal(appearance.image, '')
  globalThis.localStorage.setItem = () => { throw new Error('quota') }
  assert.throws(saveAppearance, /quota/)
})
