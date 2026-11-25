import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'

import { useAuth } from '@/contexts/AuthContext'
import { biometricLabel, GENERIC_BIOMETRIC_LABEL } from '@/security/biometricLabel'
import { mirrorLockValue } from '@/security/lockStore'
import { unthenable } from '@/utils/pluginProxy'

/**
 * Face ID / Touch ID / fingerprint for the app lock, through
 * @capgo/capacitor-native-biometric. Ported from the publisher's invoicing app
 *.
 *
 * The switch is kept with its owner's user id, so a different person signing
 * in on the same phone does not inherit it. Read synchronously (the lock must
 * be up on the first paint after a cold start) and mirrored into the secure
 * vault (security/lockStore.ts).
 */
const BIOMETRIC_ENABLED_KEY = 'orasec.biometric_enabled'
const BIOMETRIC_OWNER_KEY = 'orasec.biometric_user'

export interface BiometricContextValue {
  /** The device has biometrics enrolled and the plugin is available. */
  isAvailable: boolean
  /** The signed-in person turned biometric unlock on. */
  isEnabled: boolean
  setEnabled: (enabled: boolean) => void
  /** Ask the OS for a biometric check. True on success, false on failure / cancel. */
  verify: () => Promise<boolean>
  isVerifying: boolean
  /** What this device calls it: "Face ID", "Touch ID", "your fingerprint", … */
  label: string
}

const BiometricContext = createContext<BiometricContextValue | null>(null)

export function useBiometric(): BiometricContextValue {
  const ctx = useContext(BiometricContext)
  if (!ctx) throw new Error('useBiometric must be used within BiometricProvider')
  return ctx
}

type NativeBiometricApi = {
  isAvailable: () => Promise<{ isAvailable: boolean; biometryType?: number }>
  verifyIdentity: (opts: { reason: string; title: string; subtitle?: string; negativeButtonText?: string }) => Promise<void>
}

async function getNativeBiometric(): Promise<NativeBiometricApi | null> {
  try {
    const { Capacitor } = await import('@capacitor/core')
    if (!Capacitor.isNativePlatform()) return null
    const mod = await import('@capgo/capacitor-native-biometric')
    return mod.NativeBiometric ? (unthenable(mod.NativeBiometric as object) as unknown as NativeBiometricApi) : null
  } catch {
    return null
  }
}

function readLocal(key: string): string | null {
  try {
    return localStorage.getItem(key)
  } catch {
    return null
  }
}

export function BiometricProvider({ children }: { children: ReactNode }) {
  const { user } = useAuth()
  const currentUserId = user ? String(user.id) : null
  const [isAvailable, setIsAvailable] = useState(false)
  const [label, setLabel] = useState(GENERIC_BIOMETRIC_LABEL)
  const [owner, setOwner] = useState<string | null>(() => readLocal(BIOMETRIC_OWNER_KEY))
  const [storedEnabled, setStoredEnabled] = useState<boolean>(() => readLocal(BIOMETRIC_ENABLED_KEY) === 'true')
  const [isVerifying, setIsVerifying] = useState(false)

  useEffect(() => {
    let cancelled = false
    void (async () => {
      try {
        const biometric = await getNativeBiometric()
        if (!biometric) {
          if (!cancelled) setIsAvailable(false)
          return
        }
        const result = await biometric.isAvailable()
        if (!cancelled) {
          setIsAvailable(Boolean(result.isAvailable))
          setLabel(biometricLabel(result.biometryType))
        }
      } catch {
        if (!cancelled) setIsAvailable(false)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [])

  // Only the owner's switch counts.
  const isEnabled = storedEnabled && !!owner && owner === currentUserId

  const setEnabled = useCallback(
    (enabled: boolean) => {
      setStoredEnabled(enabled)
      setOwner(enabled ? currentUserId : null)
      try {
        if (enabled && currentUserId) {
          localStorage.setItem(BIOMETRIC_ENABLED_KEY, 'true')
          localStorage.setItem(BIOMETRIC_OWNER_KEY, currentUserId)
        } else {
          localStorage.removeItem(BIOMETRIC_ENABLED_KEY)
          localStorage.removeItem(BIOMETRIC_OWNER_KEY)
        }
      } catch {
        // storage unavailable
      }
      mirrorLockValue(BIOMETRIC_ENABLED_KEY, enabled && currentUserId ? 'true' : null)
      mirrorLockValue(BIOMETRIC_OWNER_KEY, enabled && currentUserId ? currentUserId : null)
    },
    [currentUserId],
  )

  const verify = useCallback(async (): Promise<boolean> => {
    setIsVerifying(true)
    try {
      const biometric = await getNativeBiometric()
      if (!biometric) return false
      await biometric.verifyIdentity({
        reason: 'Unlock OraSec',
        title: 'Unlock OraSec',
        negativeButtonText: 'Use PIN',
      })
      return true
    } catch {
      return false
    } finally {
      setIsVerifying(false)
    }
  }, [])

  const value = useMemo<BiometricContextValue>(
    () => ({ isAvailable, isEnabled, setEnabled, verify, isVerifying, label }),
    [isAvailable, isEnabled, setEnabled, verify, isVerifying, label],
  )

  return <BiometricContext.Provider value={value}>{children}</BiometricContext.Provider>
}

