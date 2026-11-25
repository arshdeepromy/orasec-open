import { readFileSync } from 'node:fs'
import path from 'node:path'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

/**
 * OraSec mobile app (Capacitor). Same build shape as the publisher's other apps:
 *
 * - `CAPACITOR_BUILD=1` -> base '/', the bundle the native app uses.
 * - `npm run dev` -> the browser preview at phone size (QA, port 5190). `/api` is proxied to the OraSec test
 *   instance (ORASEC_DEV_API, default http://localhost:8180). The proxy drops Origin/Referer so the API sees plain
 *   same-origin requests; the app still sends its device token exactly as on a phone.
 */
const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf-8')) as { version: string }

const devApi = process.env.ORASEC_DEV_API || 'http://localhost:8180'

export default defineConfig({
  base: '/',
  tsconfig: 'tsconfig.json',
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
  },
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(import.meta.dirname, './src'),
    },
  },
  server: {
    port: 5190,
    strictPort: true,
    host: '0.0.0.0',
    allowedHosts: true,
    fs: {
      allow: [path.resolve(import.meta.dirname, '..')],
    },
    proxy: {
      '/api': {
        target: devApi,
        changeOrigin: true,
        configure: (proxy) => {
          proxy.on('proxyReq', (proxyReq) => {
            proxyReq.removeHeader('origin')
            proxyReq.removeHeader('referer')
          })
        },
      },
    },
  },
  optimizeDeps: {
    include: ['react', 'react-dom', 'react-router-dom'],
  },
})

