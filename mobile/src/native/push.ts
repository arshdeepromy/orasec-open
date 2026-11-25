import { Capacitor } from '@capacitor/core'

/**
 * Push notifications: Firebase Cloud Messaging on Android, the Apple Push Notification service on iPhone and iPad.
 *
 * A notification only says that something is waiting ("2 new critical findings"). It never carries finding names or
 * details: those are fetched from OraSec after the app is open and unlocked.
 */
export type PushPermission = 'unsupported' | 'prompt' | 'granted' | 'denied'
export type PushTap = { kind?: string; path?: string }

/** Android notification channel. The server sends to this id (orasec/mobile/push.py). */
export const PUSH_CHANNEL = 'orasec'
const TOKEN_TIMEOUT_MS = 15000

/**
 * Gives the module, never the plugin object itself: a Capacitor plugin is a proxy that answers every property,
 * `then` included, so a promise that resolves to it fails with "PushNotifications.then() is not implemented".
 */
const load = () => import('@capacitor/push-notifications')

export function pushSupported(): boolean {
  return Capacitor.isNativePlatform()
}

export async function pushPermission(): Promise<PushPermission> {
  if (!pushSupported()) return 'unsupported'
  try {
    const { PushNotifications: push } = await load()
    const state = (await push.checkPermissions()).receive
    return state === 'granted' ? 'granted' : state === 'denied' ? 'denied' : 'prompt'
  } catch {
    return 'unsupported'
  }
}

/**
 * The address Google or Apple gives this install, or null when notifications are not allowed.
 * With `ask` the system permission question is shown if it has not been answered yet.
 */
export async function requestPushToken(ask: boolean): Promise<string | null> {
  if (!pushSupported()) return null
  const { PushNotifications: push } = await load()
  let permission = (await push.checkPermissions()).receive
  if (permission !== 'granted' && ask && permission !== 'denied') {
    permission = (await push.requestPermissions()).receive
  }
  if (permission !== 'granted') return null
  if (Capacitor.getPlatform() === 'android') {
    await push.createChannel({
      id: PUSH_CHANNEL,
      name: 'Security notifications',
      description: 'New critical findings, security alerts, approvals and overdue findings',
      importance: 4,
      visibility: 0, // private: the lock screen shows that there is a notification, not its text
    })
  }
  return new Promise<string | null>((resolve) => {
    let done = false
    const handles: Array<{ remove: () => Promise<void> }> = []
    const finish = (value: string | null) => {
      if (done) return
      done = true
      window.clearTimeout(timer)
      for (const handle of handles) void handle.remove()
      resolve(value)
    }
    const timer = window.setTimeout(() => finish(null), TOKEN_TIMEOUT_MS)
    void (async () => {
      try {
        handles.push(await push.addListener('registration', (token) => finish(token.value)))
        handles.push(await push.addListener('registrationError', () => finish(null)))
        await push.register()
      } catch {
        finish(null)
      }
    })()
  })
}

/** Called when the person taps a notification. Returns a function that stops listening. */
export async function onPushTap(handler: (tap: PushTap) => void): Promise<() => void> {
  if (!pushSupported()) return () => {}
  try {
    const { PushNotifications: push } = await load()
    const handle = await push.addListener('pushNotificationActionPerformed', (action) => {
      const data = (action.notification?.data ?? {}) as Record<string, unknown>
      handler({ kind: typeof data.kind === 'string' ? data.kind : undefined, path: typeof data.path === 'string' ? data.path : undefined })
    })
    return () => void handle.remove()
  } catch {
    return () => {}
  }
}

/** Remove OraSec's notifications from the notification list (after the app was opened). */
export async function clearDeliveredPush(): Promise<void> {
  if (!pushSupported()) return
  try {
    const { PushNotifications: push } = await load()
    await push.removeAllDeliveredNotifications()
  } catch {
    // Nothing to clear.
  }
}
