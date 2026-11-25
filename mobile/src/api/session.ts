import { secureGet, secureRemove, secureSet } from '@/native/secureStore'

/**
 * The linked-device token (`osm_…`) the OraSec server issued when this phone was linked.
 *
 * Kept in the secure vault on native — iOS Keychain (this device only) / Android Keystore-sealed storage
 * (`native/secureStore.ts`) — and in localStorage in the browser preview. Cached in memory after the first read so
 * the per-request lookup is synchronous. Revoked from the web (Profile menu → Mobile app) or by signing out here.
 */
const STORAGE_KEY = 'orasec.device.v1'
const TOKEN_PATTERN = /^osm_[A-Za-z0-9_-]{20,100}$/

let cached: string | null | undefined
const listeners = new Set<() => void>()

export function isWellFormedDeviceToken(value: unknown): value is string {
  return typeof value === 'string' && TOKEN_PATTERN.test(value)
}

export async function hydrateDeviceToken(): Promise<string | null> {
  if (cached !== undefined) return cached
  try {
    const stored = await secureGet(STORAGE_KEY)
    cached = isWellFormedDeviceToken(stored) ? stored : null
  } catch {
    cached = null
  }
  return cached
}

export function getDeviceToken(): string | null {
  return cached ?? null
}

export async function setDeviceToken(token: string): Promise<void> {
  cached = token
  try {
    await secureSet(STORAGE_KEY, token)
  } catch {
    // the token still lives in memory for this run
  }
}

export async function clearDeviceToken(): Promise<void> {
  cached = null
  try {
    await secureRemove(STORAGE_KEY)
  } catch {
    // ignore
  }
}

/** The server rejected the token (revoked from the web, expired, or unlinked). */
export function notifyDeviceRejected(): void {
  for (const listener of listeners) listener()
}

export function onDeviceRejected(listener: () => void): () => void {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

