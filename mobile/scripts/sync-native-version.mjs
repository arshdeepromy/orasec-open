#!/usr/bin/env node
/**
 * One version for the whole app: `mobile/package.json` "version".
 *
 * - The web bundle shows it in Settings → About (vite define __APP_VERSION__)
 *   and an OTA release publishes under the same number (release-ota.sh).
 * - Android reads it at build time (android/app/build.gradle).
 * - iOS needs it written into the Xcode project — this script does that, and
 *   runs as part of `npm run cap:sync` / `cap:sync:local`.
 *
 * Build number (iOS CFBundleVersion / Android versionCode) is derived the same
 * way on both platforms so it only ever goes up:  MAJOR*10000 + MINOR*100 + PATCH
 * (1.61.0 → 16100). Ship a rebuild of the same code as the next patch version.
 */
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const { version } = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(version)
if (!m) {
  console.error(`package.json version must be MAJOR.MINOR.PATCH, got ${version}`)
  process.exit(1)
}
const [major, minor, patch] = m.slice(1).map(Number)
if (minor > 99 || patch > 99) {
  console.error(`minor/patch above 99 would break the build-number scheme (${version})`)
  process.exit(1)
}
export const buildNumber = major * 10000 + minor * 100 + patch

const pbx = join(root, 'ios/App/App.xcodeproj/project.pbxproj')
const before = readFileSync(pbx, 'utf8')
const after = before
  .replace(/MARKETING_VERSION = [^;]+;/g, `MARKETING_VERSION = ${version};`)
  .replace(/CURRENT_PROJECT_VERSION = [^;]+;/g, `CURRENT_PROJECT_VERSION = ${buildNumber};`)
if (after !== before) writeFileSync(pbx, after)
console.log(`native version ${version} (build ${buildNumber})`)
