import { beforeEach, describe, expect, it, vi } from 'vitest'

/**
 * The real plugin object is a proxy that answers every property with a native call, `then` included. If code lets a
 * promise resolve to it, JavaScript calls `.then` and the app fails with "PushNotifications.then() is not implemented"
 * (seen on Android with 1.2.0 before release). This stand-in behaves the same way.
 */
const calls: string[] = []
const listeners: Record<string, (value: unknown) => void> = {}
const methods: Record<string, (...args: unknown[]) => unknown> = {
  checkPermissions: async () => ({ receive: 'granted' }),
  requestPermissions: async () => ({ receive: 'granted' }),
  createChannel: async () => undefined,
  removeAllDeliveredNotifications: async () => undefined,
  addListener: async (...args: unknown[]) => {
    listeners[args[0] as string] = args[1] as (value: unknown) => void
    return { remove: async () => undefined }
  },
  register: async () => {
    queueMicrotask(() => listeners.registration?.({ value: 'address-from-the-store' }))
  },
}
const pluginProxy = new Proxy(
  {},
  {
    get(_target, name) {
      if (typeof name !== 'string') return undefined
      if (!(name in methods)) throw new Error(`"PushNotifications.${name}()" is not implemented on android`)
      calls.push(name)
      return methods[name]
    },
  },
)

vi.mock('@capacitor/push-notifications', () => ({ PushNotifications: pluginProxy }))
vi.mock('@capacitor/core', () => ({ Capacitor: { isNativePlatform: () => true, getPlatform: () => 'android' } }))

import { clearDeliveredPush, onPushTap, pushPermission, requestPushToken } from '@/native/push'

describe('native push wrapper', () => {
  beforeEach(() => {
    calls.length = 0
  })

  it('reads the permission without treating the plugin as a promise', async () => {
    expect(await pushPermission()).toBe('granted')
  })

  it('creates the Android channel and returns the address the store gives', async () => {
    expect(await requestPushToken(true)).toBe('address-from-the-store')
    expect(calls).toContain('createChannel')
    expect(calls).toContain('register')
  })

  it('listens for taps and passes only the kind and the path on', async () => {
    const seen: unknown[] = []
    const stop = await onPushTap((tap) => seen.push(tap))
    listeners.pushNotificationActionPerformed({ notification: { data: { kind: 'alerts', path: '/attacks', other: 'x' } } })
    expect(seen).toEqual([{ kind: 'alerts', path: '/attacks' }])
    stop()
  })

  it('clears delivered notifications', async () => {
    await clearDeliveredPush()
    expect(calls).toContain('removeAllDeliveredNotifications')
  })
})
