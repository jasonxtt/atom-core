import path from 'node:path'
import fs from 'node:fs'
import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// The WebUI as one movable package (`dist/`): installed as `<config root>/ui/main/` it is
// served at `/`, as any other `ui/<name>/` at `/<name>/`. Resource URLs are relative
// (`base: './'`), so the package does not depend on where it is installed; API calls are
// same-origin absolute paths. `scripts/build-webui.mjs` adds `ui-manifest.json`.
const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const version = process.env.UI_VERSION || 'dev'
const outDir = process.env.VITE_UI_VARIANT === 'glass' ? path.resolve(__dirname, 'dist-bl') : path.resolve(__dirname, 'dist')
const devProxyTarget = process.env.ATOMDNS_DEV_TARGET || 'http://127.0.0.1'

export default defineConfig({
  base: './',
  plugins: [
    vue(),
    {
      name: 'atomdns-version-stamp',
      closeBundle() {
        const indexPath = path.join(outDir, 'index.html')
        if (!fs.existsSync(indexPath)) {
          return
        }
        const stamp = encodeURIComponent(version)
        const html = fs.readFileSync(indexPath, 'utf8')
        const stamped = html
          .replace(/\.\/app\.js(?:\?v=[^"']+)?/g, `./app.js?v=${stamp}`)
          .replace(/\.\/app\.css(?:\?v=[^"']+)?/g, `./app.css?v=${stamp}`)
        if (stamped !== html) {
          fs.writeFileSync(indexPath, stamped, 'utf8')
        }
      }
    }
  ],
  publicDir: false,
  server: {
    proxy: {
      '/api': devProxyTarget,
      '/plugins': devProxyTarget,
      '/metrics': devProxyTarget
    }
  },
  build: {
    outDir,
    emptyOutDir: true,
    sourcemap: false,
    cssCodeSplit: false,
    rollupOptions: {
      input: path.resolve(__dirname, 'index.html'),
      output: {
        entryFileNames: 'app.js',
        chunkFileNames: 'chunks/[name]-[hash].js',
        assetFileNames: (assetInfo) => {
          if (assetInfo?.names?.some((name) => name.endsWith('.css'))) {
            return 'app.css'
          }
          return 'assets/[name]-[hash][extname]'
        }
      }
    }
  }
})
