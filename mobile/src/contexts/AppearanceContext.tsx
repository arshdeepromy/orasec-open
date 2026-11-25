import { createContext, type ReactNode, useCallback, useContext, useEffect, useMemo, useState } from 'react'

import { onSystemThemeChange, systemPrefersDark } from '@/theme/systemTheme'
import {
  type AppearanceId,
  type AppearancePreference,
  applyAppearance,
  installAppearanceCss,
  isDarkAppearanceId,
  readCachedPreference,
  resolveAppearance,
  writeCachedPreference,
} from '@/theme/appearance'

/**
 * The appearance chosen on this phone (one of the looks, or Auto). Stored on the device only.
 *
 * - First paint uses the locally cached choice (no flash at launch).
 * - Signed in: the server value (`profile.getAppearance`, the same
 *   `User.appearance` the web uses) wins and is cached; changes are saved with
 *   `profile.setAppearance`, so web and app stay in sync.
 * - Signed out: the local value only.
 * - Auto follows the phone: light → OraFlows, dark → Dark.
 */
type AppearanceContextValue = {
  preference: AppearancePreference
  appearance: AppearanceId
  isDark: boolean
  setPreference: (pref: AppearancePreference) => Promise<void>
  /** Set when saving to the account failed (the look still applies here). */
  saveError: string | null
}

const AppearanceContext = createContext<AppearanceContextValue | null>(null)

export function AppearanceProvider({ children }: { children: ReactNode }) {
  const [preference, setPreferenceState] = useState<AppearancePreference>(() => readCachedPreference())
  const [prefersDark, setPrefersDark] = useState<boolean>(() => systemPrefersDark())
  const [saveError, setSaveError] = useState<string | null>(null)

  const appearance = resolveAppearance(preference, prefersDark)

  useEffect(() => {
    installAppearanceCss()
  }, [])

  useEffect(() => {
    applyAppearance(appearance)
  }, [appearance])

  useEffect(() => onSystemThemeChange(setPrefersDark), [])

  const setPreference = useCallback(
    async (pref: AppearancePreference) => {
      setPreferenceState(pref)
      writeCachedPreference(pref)
      setSaveError(null)
    },
    [],
  )

  const value = useMemo<AppearanceContextValue>(
    () => ({ preference, appearance, isDark: isDarkAppearanceId(appearance), setPreference, saveError }),
    [preference, appearance, setPreference, saveError],
  )

  return <AppearanceContext.Provider value={value}>{children}</AppearanceContext.Provider>
}

export function useAppearance(): AppearanceContextValue {
  const ctx = useContext(AppearanceContext)
  if (!ctx) throw new Error('useAppearance must be used inside AppearanceProvider')
  return ctx
}

export function useOptionalAppearance(): AppearanceContextValue | null {
  return useContext(AppearanceContext)
}

