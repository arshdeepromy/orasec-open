import { Capacitor, registerPlugin } from '@capacitor/core'

/**
 * Where the app keeps its secrets on the device: the OraSec session token
 * and the app lock state (PIN record, Face ID / fingerprint switch).
 *
 *  - iOS: the Keychain, through the app's own OraSecureStore plugin
 *    (ios/App/App/OraSecureStorePlugin.swift) — this-device-only items that
 *    never go into an iCloud / Finder backup or onto a new iPhone, wiped on the
 *    first launch after a reinstall.
 *  - Android: the same plugin (OraSecureStorePlugin.java) — values sealed with
 *    an AES-256-GCM key held in the Android Keystore; the file is excluded
 *    from backups and device transfer.
 *  - Browser preview (QA): localStorage. Never used for production secrets.
 *
 * A native build without the plugin (should not happen) falls back to
 * Capacitor Preferences so the app still works.
 *
 * Ported from the publisher's invoicing app (which used Preferences on
 * Android; OraSec seals the token on both platforms).
 */
interface OraSecureStorePlugin {
  get(options: { key: string }): Promise<{ value: string | null }>
  set(options: { key: string; value: string }): Promise<void>
  remove(options: { key: string }): Promise<void>
}

// Created on first use, not at import: tests and the browser never touch the
// native bridge.
let plugin: OraSecureStorePlugin | null = null
function vault(): OraSecureStorePlugin {
  if (!plugin) plugin = registerPlugin<OraSecureStorePlugin>('OraSecureStore')
  return plugin
}

/** True when this build keeps secrets in the Keychain / Keystore. */
export function usesSecureVault(): boolean {
  try {
    return Capacitor.isNativePlatform() && Capacitor.isPluginAvailable('OraSecureStore') === true
  } catch {
    return false
  }
}

function webStorage(): Storage | null {
  try {
    return globalThis.localStorage ?? null
  } catch {
    return null
  }
}

export async function secureGet(key: string): Promise<string | null> {
  if (usesSecureVault()) {
    const { value } = await vault().get({ key })
    return value ?? null
  }
  if (Capacitor.isNativePlatform()) {
    const { Preferences } = await import('@capacitor/preferences')
    return (await Preferences.get({ key })).value ?? null
  }
  return webStorage()?.getItem(key) ?? null
}

export async function secureSet(key: string, value: string): Promise<void> {
  if (usesSecureVault()) {
    await vault().set({ key, value })
    return
  }
  if (Capacitor.isNativePlatform()) {
    const { Preferences } = await import('@capacitor/preferences')
    await Preferences.set({ key, value })
    return
  }
  webStorage()?.setItem(key, value)
}

export async function secureRemove(key: string): Promise<void> {
  if (usesSecureVault()) {
    await vault().remove({ key })
    return
  }
  if (Capacitor.isNativePlatform()) {
    const { Preferences } = await import('@capacitor/preferences')
    await Preferences.remove({ key })
    return
  }
  webStorage()?.removeItem(key)
}

/**
 * Move a value an earlier build kept in Capacitor Preferences into the secure
 * vault, and delete the Preferences copy. Returns the moved value (or null when
 * there was nothing to move / no vault). Runs once per key: afterwards the
 * Preferences copy is gone.
 */
export async function migrateFromPreferences(key: string): Promise<string | null> {
  if (!usesSecureVault()) return null
  try {
    const { Preferences } = await import('@capacitor/preferences')
    const { value } = await Preferences.get({ key })
    if (!value) return null
    await vault().set({ key, value })
    await Preferences.remove({ key })
    return value
  } catch {
    return null
  }
}

