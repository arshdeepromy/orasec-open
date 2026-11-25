import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '@/api/http'

const native = vi.hoisted(() => ({
  supported: true,
  permission: 'granted' as string,
  token: 'device-address-0123456789' as string | null,
  asked: [] as boolean[],
}))
const server = vi.hoisted(() => ({ register: vi.fn(), unregister: vi.fn() }))
const demo = vi.hoisted(() => ({ on: false }))

vi.mock('@/native/push', () => ({
  pushSupported: () => native.supported,
  pushPermission: async () => native.permission,
  requestPushToken: async (ask: boolean) => {
    native.asked.push(ask)
    return native.token
  },
}))
vi.mock('@/api/orasec', () => ({ orasec: { pushRegister: server.register, pushUnregister: server.unregister } }))
vi.mock('@/demo/session', () => ({ isDemoSession: () => demo.on }))

import { isPushOptedIn, refreshPushRegistration, safeTapPath, setPushOptIn, turnOffPush, turnOnPush } from '@/notifications/pushController'

const STATE = { available: true, registered: true, settings: { critical: true, approvals: true, alerts: true, overdue: true } }

describe('push controller', () => {
  beforeEach(() => {
    localStorage.clear()
    Object.assign(native, { supported: true, permission: 'granted', token: 'device-address-0123456789', asked: [] })
    demo.on = false
    server.register.mockReset().mockResolvedValue(STATE)
    server.unregister.mockReset().mockResolvedValue({ ...STATE, registered: false })
  })

  it('switching on asks the phone, gives the address to OraSec and remembers the choice', async () => {
    const result = await turnOnPush()
    expect(result).toEqual({ ok: true, state: STATE })
    expect(native.asked).toEqual([true])
    expect(server.register).toHaveBeenCalledWith('device-address-0123456789')
    expect(isPushOptedIn()).toBe(true)
  })

  it('says so when the phone has notifications switched off for the app', async () => {
    native.token = null
    native.permission = 'denied'
    const result = await turnOnPush()
    expect(result.ok).toBe(false)
    expect(result).toMatchObject({ reason: 'denied' })
    expect(server.register).not.toHaveBeenCalled()
    expect(isPushOptedIn()).toBe(false)
  })

  it('tells a "no" to the system question apart from a phone that gave no address', async () => {
    native.token = null
    native.permission = 'prompt' // Android after the first "Don't allow": it may be asked again
    const declined = await turnOnPush()
    expect(declined).toMatchObject({ ok: false, reason: 'denied' })
    expect(declined.ok ? '' : declined.message).toMatch(/did not allow/)
    native.permission = 'granted'
    const noAddress = await turnOnPush()
    expect(noAddress).toMatchObject({ ok: false, reason: 'error' })
    expect(noAddress.ok ? '' : noAddress.message).toMatch(/notification address/)
    expect(server.register).not.toHaveBeenCalled()
  })

  it('does nothing in the demo, in the browser preview, or when the server has no notifications', async () => {
    demo.on = true
    expect(await turnOnPush()).toMatchObject({ ok: false, reason: 'unavailable' })
    demo.on = false
    native.supported = false
    expect(await turnOnPush()).toMatchObject({ ok: false, reason: 'unsupported' })
    native.supported = true
    server.register.mockRejectedValue(new ApiError({ status: 404 }))
    expect(await turnOnPush()).toMatchObject({ ok: false, reason: 'unavailable' })
    expect(native.asked).toEqual([true])
    expect(isPushOptedIn()).toBe(false)
  })

  it('switching off forgets the choice even when OraSec cannot be reached', async () => {
    setPushOptIn(true)
    server.unregister.mockRejectedValue(new ApiError({ status: 0 }))
    expect(await turnOffPush()).toBeNull()
    expect(isPushOptedIn()).toBe(false)
  })

  it('on start it sends the address again without asking, and only when switched on and allowed', async () => {
    await refreshPushRegistration()
    expect(server.register).not.toHaveBeenCalled() // not switched on
    setPushOptIn(true)
    native.permission = 'denied'
    await refreshPushRegistration()
    expect(server.register).not.toHaveBeenCalled()
    native.permission = 'granted'
    await refreshPushRegistration()
    expect(native.asked).toEqual([false])
    expect(server.register).toHaveBeenCalledTimes(1)
    server.register.mockRejectedValue(new ApiError({ status: 0 }))
    await expect(refreshPushRegistration()).resolves.toBeUndefined() // offline is not an error
  })

  it('a notification can only open one of the app’s own screens', () => {
    expect(safeTapPath('/vulns')).toBe('/vulns')
    expect(safeTapPath('/my-work')).toBe('/my-work')
    for (const bad of [undefined, '', 'https://evil.example/', '//evil.example', '/vulns/../link', '/link', 'javascript:alert(1)']) {
      expect(safeTapPath(bad)).toBeNull()
    }
  })
})
