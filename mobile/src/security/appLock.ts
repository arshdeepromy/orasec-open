import { useSyncExternalStore } from 'react'

import { mirrorLockValue } from '@/security/lockStore'

/**
 * App lock settings for the signed-in person on this device:
 *
 *  - `enabled`  — the app opens with the PIN / Face ID / fingerprint
 *                 (Settings → App lock). Offered on the first sign-in.
 *  - `timeoutMs` — lock again when the app comes back after this long in the
 *                 background (0 = every time it leaves the screen).
 *
 * No record for a person = they have not decided yet (the PIN setup is
 * offered). Kept with the owner's user id, so a different person signing in
 * on the same phone starts fresh. Read synchronously (first paint), mirrored
 * into the secure vault (lockStore.ts).
 */
const STORAGE_KEY = 'orasec.app_lock.v1'

export const RELOCK_OPTIONS: ReadonlyArray<{ ms: number; label: string }> = [
  { ms: 0, label: 'Immediately' },
  { ms: 60_000, label: 'After 1 minute' },
  { ms: 5 * 60_000, label: 'After 5 minutes' },
  { ms: 15 * 60_000, label: 'After 15 minutes' },
]

export const DEFAULT_RELOCK_MS = 60_000

export interface AppLockSettings {
  userId: string
  enabled: boolean
  timeoutMs: number
}

const listeners = new Set<() => void>()
let version = 0

function readRaw(): AppLockSettings | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return null
    const parsed = JSON.parse(raw) as Partial<AppLockSettings>
    if (typeof parsed.userId !== 'string' || typeof parsed.enabled !== 'boolean') return null
    const timeoutMs = RELOCK_OPTIONS.some((o) => o.ms === parsed.timeoutMs) ? (parsed.timeoutMs as number) : DEFAULT_RELOCK_MS
    return { userId: parsed.userId, enabled: parsed.enabled, timeoutMs }
  } catch {
    return null
  }
}

/** This person's settings, or null when they have not decided yet. */
export function getAppLockSettings(userId: string | null | undefined): AppLockSettings | null {
  if (!userId) return null
  const record = readRaw()
  return record && record.userId === userId ? record : null
}

export function saveAppLockSettings(settings: AppLockSettings | null): void {
  const value = settings ? JSON.stringify(settings) : null
  try {
    if (value) localStorage.setItem(STORAGE_KEY, value)
    else localStorage.removeItem(STORAGE_KEY)
  } catch {
    // storage unavailable
  }
  mirrorLockValue(STORAGE_KEY, value)
  version += 1
  for (const fn of listeners) fn()
}

export function updateAppLockSettings(userId: string, patch: Partial<Omit<AppLockSettings, 'userId'>>): AppLockSettings {
  const current = getAppLockSettings(userId) ?? { userId, enabled: false, timeoutMs: DEFAULT_RELOCK_MS }
  const next = { ...current, ...patch, userId }
  saveAppLockSettings(next)
  return next
}

function subscribe(fn: () => void) {
  listeners.add(fn)
  return () => listeners.delete(fn)
}

/** Re-renders when the settings change (in this tab). */
export function useAppLockSettings(userId: string | null | undefined): AppLockSettings | null {
  useSyncExternalStore(subscribe, () => version)
  return getAppLockSettings(userId)
}

/** Notify subscribers after a change made elsewhere (PIN set / cleared). */
export function notifyAppLockChanged(): void {
  version += 1
  for (const fn of listeners) fn()
}

