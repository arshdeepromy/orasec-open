// Render the OraSec app icon artwork with headless Chromium (Playwright from ~/playwright-tests).
//   node scripts/make-orasec-icon.mjs            -> store-assets/app-icon-1024.png (opaque, full bleed, for iOS / Play)
//                                                   src/assets/orasec-mark-256.png (rounded tile, transparent corners)
//                                                   store-assets/play-store-icon-512.png
// The shield + magnifier is the OraSec symbol (orasec/static/orasec/img/symbol.svg) on the dark console tile.
import { mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium } from 'playwright'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
mkdirSync(join(root, 'store-assets'), { recursive: true })

const art = (size, radius) => `<!doctype html><html><body style="margin:0;background:transparent">
<div style="width:${size}px;height:${size}px;border-radius:${radius}px;overflow:hidden;position:relative;
  background: radial-gradient(120% 120% at 18% 10%, #17413b 0%, #0d1f1c 45%, #070f0e 100%);">
  <div style="position:absolute;inset:0;background:radial-gradient(60% 60% at 50% 55%, rgba(0,168,144,.28) 0%, rgba(0,168,144,0) 70%)"></div>
  <svg viewBox="0 0 64 64" width="${size * 0.62}" height="${size * 0.62}" style="position:absolute;left:${size * 0.19}px;top:${size * 0.195}px;filter:drop-shadow(0 ${size * 0.012}px ${size * 0.03}px rgba(0,0,0,.45))">
    <defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#19d3b5"/><stop offset="1" stop-color="#00927e"/></linearGradient></defs>
    <path d="M32 3 L57 12 V30 C57 45.5 46.5 56.5 32 61 C17.5 56.5 7 45.5 7 30 V12 Z" fill="url(#g)"/>
    <path d="M32 9.5 L51 16.4 V30.2 C51 42 43.2 50.6 32 54.4 Z" fill="#004740" opacity=".32"/>
    <circle cx="32" cy="31" r="10.5" fill="none" stroke="#fff" stroke-width="5"/>
    <path d="M39.5 38.5 L46 45" stroke="#fff" stroke-width="5" stroke-linecap="round"/>
  </svg>
</div></body></html>`

const browser = await chromium.launch()
const page = await browser.newPage({ deviceScaleFactor: 1 })
const shot = async (size, radius, out, omit) => {
  await page.setViewportSize({ width: size, height: size })
  await page.setContent(art(size, radius))
  await page.screenshot({ path: out, omitBackground: omit, clip: { x: 0, y: 0, width: size, height: size } })
  console.log('wrote', out)
}
await shot(1024, 0, join(root, 'store-assets/app-icon-1024.png'), false)
await shot(512, 0, join(root, 'store-assets/play-store-icon-512.png'), false)
await shot(256, 58, join(root, 'src/assets/orasec-mark-256.png'), true)
await browser.close()

