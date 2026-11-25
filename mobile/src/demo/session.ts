import { getDeviceToken } from '@/api/session'
import { sha256 } from '@/utils/sha256'

/**
 * Demo session markers (kept apart from the sample data so the main bundle stays small: the data and the demo
 * request handler load only when a demo session starts).
 */
export const DEMO_TOKEN = 'osm_demo_sample_data_only_000000000000'
// SHA-256 of "orasec-demo:" + the 10-character reviewer code (the code itself is only in the private review notes).
const DEMO_CODE_SHA256 = 'fd05b2c7ef54c5329cf61779d15bbc23939da5c27c61a1483582224f714fe427'

export function isDemoToken(token: string | null | undefined): boolean {
  return typeof token === 'string' && token.startsWith('osm_demo_')
}

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')

/** True when `code` (as typed, with or without the dash) is the reviewer code. */
export async function isDemoCode(code: unknown): Promise<boolean> {
  if (typeof code !== 'string') return false
  const clean = code.toUpperCase().replace(/[^A-Z0-9]/g, '')
  if (clean.length !== 10) return false
  return hex(await sha256(new TextEncoder().encode(`orasec-demo:${clean}`))) === DEMO_CODE_SHA256
}

/** True while the phone is in the demo (sample data). Links to the real web console are hidden then. */
export function isDemoSession(): boolean {
  return isDemoToken(getDeviceToken())
}
