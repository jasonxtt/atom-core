import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// The WebUI as one movable package (`dist/`): installed as `<config root>/ui/main/` it is
// served at `/`, as any other `ui/<name>/` at `/<name>/`. Resource URLs are relative
// (`base: './'`) and routes are hash routes, so the package does not depend on where it is
// installed; API calls are same-origin absolute paths. `scripts/build-webui.mjs` adds
// `ui-manifest.json`.
const here = path.dirname(fileURLToPath(import.meta.url))
const version = process.env.UI_VERSION || 'dev'
const outDir = path.resolve(here, 'dist')
// `npm run dev` passes API calls to a running atomdns (its management address).
const devTarget = process.env.ATOMDNS_DEV_TARGET || 'http://127.0.0.1:9099'

export default defineConfig({
  base: './',
  define: { __UI_VERSION__: JSON.stringify(version) },
  plugins: [
    vue(),
    {
      // Browsers keep `app.js` / `app.css` across package updates; the version in the URL
      // makes a new package load its own files.
      name: 'atom-version-stamp',
      closeBundle() {
        const index = path.join(outDir, 'index.html')
        if (!fs.existsSync(index)) return
        const stamp = encodeURIComponent(version)
        const html = fs.readFileSync(index, 'utf8')
        fs.writeFileSync(
          index,
          html
            .replace(/\.\/app\.js(?:\?v=[^"']+)?/g, `./app.js?v=${stamp}`)
            .replace(/\.\/app\.css(?:\?v=[^"']+)?/g, `./app.css?v=${stamp}`),
          'utf8'
        )
      }
    }
  ],
  publicDir: false,
  server: { proxy: { '/api': devTarget } },
  build: {
    outDir,
    emptyOutDir: true,
    sourcemap: false,
    cssCodeSplit: false,
    rollupOptions: {
      input: path.resolve(here, 'index.html'),
      output: {
        entryFileNames: 'app.js',
        chunkFileNames: 'chunks/[name]-[hash].js',
        assetFileNames: (asset) =>
          asset.names?.some((name) => name.endsWith('.css')) ? 'app.css' : 'assets/[name]-[hash][extname]'
      }
    }
  }
})
