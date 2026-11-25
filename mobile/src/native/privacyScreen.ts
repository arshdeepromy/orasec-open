import { Capacitor, registerPlugin } from '@capacitor/core'
import { useEffect, useRef } from 'react'

/**
 * Screenshot / screen-recording / app-switcher protection for sensitive
 * screens.
 *
 * Any screen marks itself sensitive by rendering an element with the
 * `data-sensitive-screen` attribute (the signing screens do; the app lock and
 * PIN screens do). While at least one such element is in the document:
 *
 *  - Android: FLAG_SECURE on the window (OraPrivacyPlugin.java) — screenshots,
 *    screen recordings and the recent-apps thumbnail are black.
 *  - iOS: OraPrivacyPlugin.swift covers the window with a plain overlay when
 *    the app goes to the background (so the app-switcher snapshot shows the
 *    overlay, not the document) and while the screen is being recorded or
 *    mirrored. iOS offers no way to block a screenshot itself.
 *
 * On iOS the background overlay is also on whenever the app lock is enabled
 * (`extraBackgroundOverlay`), since a locked app should not show its last
 * screen in the switcher. Android keeps screenshots of ordinary screens.
 *
 * Browser preview: no-op.
 */
interface OraPrivacyPlugin {
  setSecure(options: { enabled: boolean }): Promise<void>
}

let plugin: OraPrivacyPlugin | null = null
function privacy(): OraPrivacyPlugin {
  if (!plugin) plugin = registerPlugin<OraPrivacyPlugin>('OraPrivacy')
  return plugin
}

export const SENSITIVE_SELECTOR = '[data-sensitive-screen]'

/** True when the document currently shows a sensitive screen. */
export function hasSensitiveScreen(root: ParentNode = document): boolean {
  try {
    return root.querySelector(SENSITIVE_SELECTOR) !== null
  } catch {
    return false
  }
}

/** Whether the native protection should be on, per platform. */
export function shouldProtect(platform: string, sensitive: boolean, extraBackgroundOverlay: boolean): boolean {
  if (platform === 'ios') return sensitive || extraBackgroundOverlay
  if (platform === 'android') return sensitive
  return false
}

let lastApplied: boolean | null = null

export async function setScreenProtection(enabled: boolean): Promise<void> {
  if (!Capacitor.isNativePlatform() || !Capacitor.isPluginAvailable('OraPrivacy')) return
  if (lastApplied === enabled) return
  lastApplied = enabled
  try {
    await privacy().setSecure({ enabled })
  } catch {
    lastApplied = null
  }
}

/** Test helper. */
export function _resetPrivacyScreen(): void {
  lastApplied = null
}

/**
 * Watch the document for `data-sensitive-screen` elements and keep the native
 * protection in step. Mount once, near the root (App.tsx).
 */
export function usePrivacyScreen(extraBackgroundOverlay: boolean): void {
  const extra = useRef(extraBackgroundOverlay)
  extra.current = extraBackgroundOverlay

  useEffect(() => {
    if (!Capacitor.isNativePlatform()) return
    const platform = Capacitor.getPlatform()
    let frame = 0
    const apply = () => {
      frame = 0
      void setScreenProtection(shouldProtect(platform, hasSensitiveScreen(), extra.current))
    }
    const schedule = () => {
      if (!frame) frame = requestAnimationFrame(apply)
    }
    apply()
    const observer = new MutationObserver(schedule)
    observer.observe(document.body, {
      subtree: true,
      childList: true,
      attributes: true,
      attributeFilter: ['data-sensitive-screen'],
    })
    return () => {
      observer.disconnect()
      if (frame) cancelAnimationFrame(frame)
    }
  }, [])

  // The app lock was switched on / off: re-evaluate (iOS overlay).
  useEffect(() => {
    if (!Capacitor.isNativePlatform()) return
    void setScreenProtection(shouldProtect(Capacitor.getPlatform(), hasSensitiveScreen(), extraBackgroundOverlay))
  }, [extraBackgroundOverlay])
}

