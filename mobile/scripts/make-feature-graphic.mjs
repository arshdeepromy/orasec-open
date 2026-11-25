// Renders the Google Play feature graphic (1024x500) to store-assets/feature-graphic-1024x500.png.
// Run: node scripts/make-feature-graphic.mjs  (needs Playwright)
import { chromium } from 'playwright'
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const mark = fs.readFileSync(path.join(root, 'src/assets/orasec-mark-256.png')).toString('base64');
const html = `<!doctype html><html><body style="margin:0">
<div style="width:1024px;height:500px;box-sizing:border-box;padding:0 80px;display:flex;align-items:center;gap:56px;
  font-family:'IBM Plex Sans',system-ui,sans-serif;color:#EEF6F4;
  background:radial-gradient(circle at 18% 10%,rgba(25,194,165,.30),rgba(0,0,0,0) 45%),radial-gradient(circle at 90% 90%,rgba(0,168,144,.18),rgba(0,0,0,0) 40%),#0B1312">
  <img src="data:image/png;base64,${mark}" style="width:200px;height:200px">
  <div>
    <div style="font-size:72px;font-weight:700;letter-spacing:-1px">OraSec</div>
    <div style="font-size:30px;color:#A9C2BD;margin-top:8px">Security operations</div>
    <div style="font-size:22px;color:#6FE3CE;margin-top:26px">Vulnerabilities · Attacks · Risk · ISO 27001</div>
  </div>
</div></body></html>`;
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1024, height: 500 } });
await page.setContent(html);
await page.screenshot({ path: path.join(root, 'store-assets/feature-graphic-1024x500.png') });
await browser.close();
console.log('wrote store-assets/feature-graphic-1024x500.png');

