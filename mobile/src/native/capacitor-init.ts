import { Capacitor } from '@capacitor/core'

/**
 * Initialise Capacitor-specific native features.
 *
 * Call this once before React renders. On web it's a no-op so the app
 * stays fully runnable in the browser.
 */
export async function capacitorInit(): Promise<void> {
  const platform = Capacitor.getPlatform()
  const isNative = Capacitor.isNativePlatform()

  if (!isNative) {
    // Running in a browser — nothing to configure
    return
  }

  // --- Status Bar ---
  // Only the background is set here. The *style* (light vs dark content) is
  // owned by KonstaShell, which knows whether the current surface is light or
  // dark; setting a fixed style here would fight it on every navigation.
  // setBackgroundColor is a no-op from Android 15, where the bars are always
  // transparent — kept for older devices.
  // Nothing to do on Android: from Android 15 the bars are always transparent,
  // setBackgroundColor is a no-op, and setting a dark colour made the platform
  // force light (white) bar content, which is unreadable on the app's light
  // screens. KonstaShell drives appearance per surface instead.
  if (platform === 'ios') {
    try {
      const { StatusBar, Style } = await import('@capacitor/status-bar')
      await StatusBar.setStyle({ style: Style.Light })
    } catch {
      // Plugin not available — ignore
    }
  }

  // --- Splash Screen ---
  // Hide after a short delay so the first paint has time to render
  try {
    const { SplashScreen } = await import('@capacitor/splash-screen')
    setTimeout(async () => {
      try {
        await SplashScreen.hide({ fadeOutDuration: 300 })
      } catch {
        // ignore
      }
    }, 500)
  } catch {
    // Plugin not available — ignore
  }

  // --- App state listeners (resume / pause) ---
  try {
    const { App } = await import('@capacitor/app')

    App.addListener('appStateChange', ({ isActive }) => {
      if (isActive) {
        // App resumed — could refresh auth token, sync data, etc.
        console.debug('[capacitor-init] App resumed')
      } else {
        // App paused — save any pending state
        console.debug('[capacitor-init] App paused')
      }
    })

    // --- Hardware back button (Android) ---
    // Open sheets / drawers / wizard steps close first, then the router
    // decides (see native/backButton.ts and AndroidBackHandler).
    const { handleBackButton } = await import('@/native/backButton')
    App.addListener('backButton', ({ canGoBack }) => {
      if (handleBackButton()) return
      if (canGoBack) {
        window.history.back()
      } else {
        // At the root of the app — minimise instead of exiting
        App.minimizeApp()
      }
    })
  } catch {
    // Plugin not available — ignore
  }

  // --- Keyboard (Android) ---
  if (platform === 'android') {
    try {
      const { Keyboard } = await import('@capacitor/keyboard')
      // Keyboard plugin auto-configures from capacitor.config.ts
      // Additional runtime listeners can be added here if needed
      Keyboard.addListener('keyboardWillShow', () => {
        document.body.classList.add('keyboard-open')
      })
      Keyboard.addListener('keyboardWillHide', () => {
        document.body.classList.remove('keyboard-open')
      })
      // The WebView shrinks to the space above the keyboard but, unlike iOS,
      // doesn't bring the focused field back into view — on a landscape
      // tablet the keyboard covers half the screen and hides the sign-in
      // password box. Centre the focused field once the keyboard is up.
      Keyboard.addListener('keyboardDidShow', () => {
        revealFocusedField()
      })
    } catch {
      // Plugin not available — ignore
    }
  }

  console.debug(`[capacitor-init] Initialised for platform: ${platform}`)
}

/** Scroll the focused input into the visible area if the keyboard hides it. */
export function revealFocusedField(): void {
  const el = document.activeElement as HTMLElement | null
  if (!el) return
  const editable =
    el.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName)
  if (!editable) return
  const r = el.getBoundingClientRect()
  const visible = window.visualViewport?.height ?? window.innerHeight
  if (r.bottom > visible - 8 || r.top < 0) {
    el.scrollIntoView({ block: 'center', behavior: 'smooth' })
  }
}
