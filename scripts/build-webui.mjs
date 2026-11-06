// Builds the WebUI package: webui-log/dist/{index.html, app.js, app.css, chunks/, assets/, ui-manifest.json}.
// Installed as `<config root>/ui/main/` it is served at `/`; as any other `ui/<name>/` at `/<name>/`.
//   npm run build            the package directory only
//   npm run build:package    and release/atomdns-webui.tar.gz (the package files at the top level)
// UI_VERSION overrides the version (default: git describe, then "dev"). The archive needs `tar`.
import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { ARCHIVE_NAME, buildManifest, validVersion } from './external-ui-manifest.mjs'

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const workspace = path.join(repository, 'webui-log')
const output = path.join(workspace, process.env.VITE_UI_VARIANT === 'glass' ? 'dist-bl' : 'dist')

function describe() {
  try {
    return execFileSync('git', ['describe', '--tags', '--match', 'v*', '--always', '--dirty'], { cwd: repository, encoding: 'utf8' }).trim()
  } catch {
    return 'dev'
  }
}

const version = process.env.UI_VERSION || describe()
if (!validVersion(version)) throw new Error(`invalid UI version: ${JSON.stringify(version)}`)

execFileSync('npx', ['vite', 'build'], {
  cwd: workspace,
  stdio: 'inherit',
  env: { ...process.env, UI_VERSION: version }
})
if (!existsSync(path.join(output, 'index.html'))) throw new Error('the build produced no index.html')
writeFileSync(path.join(output, 'ui-manifest.json'), `${JSON.stringify(buildManifest({ version }), null, 2)}\n`)
console.log(`WebUI ${version}: ${output}`)

if (process.argv.includes('--package')) {
  const releaseDirectory = path.join(repository, 'release')
  mkdirSync(releaseDirectory, { recursive: true })
  const archive = path.join(releaseDirectory, process.env.VITE_UI_VARIANT === 'glass' ? 'atomdns-webui-bl.tar.gz' : ARCHIVE_NAME)
  rmSync(archive, { force: true })
  // ustar, numeric root ownership, sorted names, no `./` prefix and (on macOS) no AppleDouble
  // files: the updater accepts plain files and directories only.
  const gnu = execFileSync('tar', ['--version'], { encoding: 'utf8' }).includes('GNU tar')
  const entries = readdirSync(output).sort()
  const args = gnu
    ? ['--format=ustar', '--owner=0', '--group=0', '--numeric-owner', '--sort=name', '-czf', archive, '-C', output, ...entries]
    : ['--format', 'ustar', '--uid', '0', '--gid', '0', '--numeric-owner', '-czf', archive, '-C', output, ...entries]
  execFileSync('tar', args, { stdio: 'inherit', env: { ...process.env, COPYFILE_DISABLE: '1' } })
  console.log(`archive: ${archive}`)
}
