/**
 * Is the phone in dark mode?
 *
 * Android's WebView kept answering `prefers-color-scheme: light` even with the
 * system dark theme on (seen on Android 14 and 15 emulators, Nov 2026), so
 * "Auto" never went dark. MainActivity exposes the real night-mode flag as
 * `window.OraSystemTheme.isNight()` (available before the page's scripts run)
 * and dispatches `ora:system-theme` when it changes. Everywhere else (iOS,
 * browser preview) the media query is right and is used as is.
 */

type NativeTheme = { isNight?: () => boolean }

function native(): NativeTheme | null {
  if (typeof window === 'undefined') return null
  const t = (window as unknown as { OraSystemTheme?: NativeTheme }).OraSystemTheme
  return t && typeof t.isNight === 'function' ? t : null
}

const query = () =>
  typeof window !== 'undefined' && window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null

export function systemPrefersDark(): boolean {
  const n = native()
  if (n) {
    try {
      return Boolean(n.isNight!())
    } catch {
      /* fall through to the media query */
    }
  }
  return query()?.matches ?? false
}

/** Calls back with the new value whenever the system theme changes. */
export function onSystemThemeChange(cb: (dark: boolean) => void): () => void {
  const mq = query()
  const fromQuery = () => cb(systemPrefersDark())
  const fromNative = (e: Event) => cb(Boolean((e as CustomEvent<boolean>).detail))
  mq?.addEventListener('change', fromQuery)
  window.addEventListener('ora:system-theme', fromNative)
  return () => {
    mq?.removeEventListener('change', fromQuery)
    window.removeEventListener('ora:system-theme', fromNative)
  }
}

