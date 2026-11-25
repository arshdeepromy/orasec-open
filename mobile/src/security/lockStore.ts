import { secureGet, secureRemove, secureSet, usesSecureVault } from '@/native/secureStore'

/**
 * The app lock's device state — the PIN record, the Face ID / fingerprint
 * switch and the lock settings — is read synchronously from localStorage (the
 * lock has to be up on the first paint after a cold start). The WebView's
 * storage can be cleared by the system, so on a device the secure vault
 * (iOS Keychain / Android Keystore-sealed store, `native/secureStore.ts`) is
 * the real store and localStorage only a copy:
 *
 *  - hydrateLockState() runs before React renders (main.tsx) and makes
 *    localStorage match the vault (a value missing from the vault is removed);
 *  - every write goes to both (mirrorLockValue).
 *
 * Ported from the publisher's invoicing app (iOS-only there; OraSec
 * uses the vault on Android too).
 */
export const LOCK_STATE_KEYS = [
  'orasec.app_pin.v1',
  'orasec.biometric_enabled',
  'orasec.biometric_user',
  'orasec.app_lock.v1',
] as const

export type LockStateKey = (typeof LOCK_STATE_KEYS)[number]

export async function hydrateLockState(): Promise<void> {
  if (!usesSecureVault()) return
  for (const key of LOCK_STATE_KEYS) {
    try {
      const value = await secureGet(key)
      if (value === null) localStorage.removeItem(key)
      else localStorage.setItem(key, value)
    } catch {
      // Vault unreadable (should not happen after first unlock): leave the
      // copy alone. A missing PIN only ever leads to a sign-out (AppLockGate).
    }
  }
}

export function mirrorLockValue(key: LockStateKey, value: string | null): void {
  if (!usesSecureVault()) return
  void (value === null ? secureRemove(key) : secureSet(key, value)).catch(() => {
    // Best effort: if the vault write fails the next cold start finds no PIN
    // and signs the person out, which is the safe direction.
  })
}

