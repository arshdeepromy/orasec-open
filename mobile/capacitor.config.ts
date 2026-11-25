import type { CapacitorConfig } from '@capacitor/cli'

/**
 * Capacitor configuration for the OraSec mobile app.
 *
 * App id `nz.co.oraflows.orasec` is permanent once on Google Play and is the SAME on Android and iOS.
 *
 * Store builds (STORE_BUILD=1, set by `npm run android:release` / `android:bundle` / `ios:release`) are HTTPS-only:
 * no cleartext, no mixed content. Debug builds allow http so the emulator can reach a test server on the build machine
 * (http://10.0.2.2:8180).
 *
 * The app talks to whichever OraSec server the person enters (src/config/serverConfig.ts) with plain fetch calls, so
 * no host is listed here: the WebView itself never navigates away from the bundled app.
 */
const serverUrl = process.env.CAPACITOR_SERVER_URL || undefined
const storeBuild = process.env.STORE_BUILD === '1'

const config: CapacitorConfig = {
  appId: 'nz.co.oraflows.orasec',
  appName: 'OraSec',
  webDir: 'dist',
  backgroundColor: '#0D1514',
  server: {
    url: serverUrl,
    cleartext: !storeBuild,
    androidScheme: 'https',
    // Shown instead of the app when the WebView is too old to run it (see android.minWebViewVersion).
    errorPath: 'webview-update.html',
  },
  android: {
    allowMixedContent: !storeBuild,
    // The UI needs a Chromium 111+ WebView (Tailwind 4 / modern CSS and JS). Android 7-9 phones get updated
    // WebViews from Google Play (Android 7 stops at 119); an outdated one shows public/webview-update.html.
    minWebViewVersion: 111,
    // Every plugin except @capacitor/status-bar: on Android the bars are driven by the app's own OraStatusBarPlugin
    // (edge-to-edge, WindowInsetsController). iOS still uses it. Keep this list in sync with package.json.
    includePlugins: [
      '@capacitor/app',
      '@capacitor/browser',
      '@capacitor/haptics',
      '@capacitor/keyboard',
      '@capacitor/network',
      '@capacitor/preferences',
      '@capacitor/push-notifications',
      '@capacitor/splash-screen',
      '@capgo/capacitor-native-biometric',
    ],
  },
  ios: {
    contentInset: 'never',
  },
  plugins: {
    SplashScreen: {
      launchShowDuration: 1200,
      backgroundColor: '#0D1514',
      launchAutoHide: true,
      launchFadeOutDuration: 300,
    },
    // Show a notification also while the app is open (iOS hides it otherwise).
    PushNotifications: {
      presentationOptions: ['badge', 'sound', 'alert'],
    },
    StatusBar: {},
    // Android insets are mirrored into --android-inset-* by MainActivity.
    SystemBars: {
      insetsHandling: 'disable',
    },
    Keyboard: {
      resize: 'body',
      style: 'dark',
      resizeOnFullScreen: false,
    },
  },
}

export default config
