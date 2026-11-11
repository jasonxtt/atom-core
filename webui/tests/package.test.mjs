// The WebUI package: what the host reads from it (ui_manifest.rs) and how it is built.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

import { API_LEVEL, ARCHIVE_NAME, buildManifest, validVersion } from '../../scripts/external-ui-manifest.mjs'

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8')

test('the manifest has the fields the host judges', () => {
  const manifest = buildManifest({ version: 'v1.2.3-4-gabc', now: new Date('2026-10-17T10:11:12.345Z') })
  assert.deepEqual(manifest, {
    manifest_schema: 1,
    ui_version: 'v1.2.3-4-gabc',
    built_at: '2026-10-17T10:11:12Z',
    api_level: API_LEVEL,
    requires_api_level: API_LEVEL
  })
  for (const bad of ['', '  ', 'a\nb', 'x'.repeat(65), undefined, 5]) {
    assert.equal(validVersion(bad), false, String(bad))
    assert.throws(() => buildManifest({ version: bad }))
  }
  assert.equal(ARCHIVE_NAME, 'atom-webui.tar.gz')
})

test('the build script and the host agree on the interface level', () => {
  const host = read('../../rust/native-host/src/ui_manifest.rs')
  assert.equal(Number(host.match(/pub\(crate\) const HOST_API_LEVEL: u64 = (\d+);/)[1]), API_LEVEL)
  assert.equal(Number(host.match(/pub\(crate\) const MIN_UI_API_LEVEL: u64 = (\d+);/)[1]), API_LEVEL)
})

test('one build makes a package that works under any mount name', () => {
  const config = read('../vite.config.ts')
  assert.match(config, /base: '\.\/'/)
  assert.match(config, /path\.resolve\(here, 'dist'\)/)
  const code = config.split('\n').filter((line) => !line.trim().startsWith('//')).join('\n')
  assert.doesNotMatch(code, /\/main\/|native-host\/ui/, 'nothing depends on a mount name or the program tree')
  assert.match(read('../src/router.ts'), /createWebHashHistory\(\)/, 'routes need no help from the host')
  const pkg = JSON.parse(read('../package.json'))
  assert.equal(pkg.scripts.build, 'node ../scripts/build-webui.mjs')
  assert.equal(pkg.scripts['build:package'], 'node ../scripts/build-webui.mjs --package')
  const script = read('../../scripts/build-webui.mjs')
  assert.match(script, /ui-manifest\.json/)
  assert.match(script, /--format=ustar/)
  assert.match(script, /COPYFILE_DISABLE/)
})

test('the API types are generated from the specification as it is', () => {
  const pkg = JSON.parse(read('../package.json'))
  assert.equal(pkg.scripts['gen:api'], 'openapi-typescript ../docs/api/openapi.yaml -o src/api/schema.ts')
})
