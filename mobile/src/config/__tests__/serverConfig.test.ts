import { beforeEach, describe, expect, it, vi } from 'vitest'

const env = vi.hoisted(() => ({ native: true, saved: null as string | null, token: null as string | null }))
const prefs = vi.hoisted(() => ({ get: vi.fn(), set: vi.fn(), remove: vi.fn() }))
const session = vi.hoisted(() => ({ clearDeviceToken: vi.fn(), hydrateDeviceToken: vi.fn() }))

vi.mock('@capacitor/core', () => ({ Capacitor: { isNativePlatform: () => env.native, getPlatform: () => 'ios' } }))
vi.mock('@capacitor/preferences', () => ({ Preferences: prefs }))
vi.mock('@/api/session', () => session)

const load = async (vars: Record<string, string> = {}) => {
  vi.resetModules()
  vi.unstubAllEnvs()
  for (const [k, v] of Object.entries(vars)) vi.stubEnv(k, v)
  return import('@/config/serverConfig')
}

const reply = (status: number, body: unknown) => ({ ok: status >= 200 && status < 300, status, json: async () => body }) as Response

describe('server address', () => {
  beforeEach(() => {
    Object.assign(env, { native: true, saved: null, token: null })
    prefs.get.mockReset().mockImplementation(async () => ({ value: env.saved }))
    prefs.set.mockReset().mockImplementation(async ({ value }: { value: string }) => {
      env.saved = value
    })
    prefs.remove.mockReset().mockImplementation(async () => {
      env.saved = null
    })
    session.clearDeviceToken.mockReset().mockResolvedValue(undefined)
    session.hydrateDeviceToken.mockReset().mockImplementation(async () => env.token)
  })

  it('accepts a host name, adds https, keeps only the origin', async () => {
    const c = await load()
    expect(c.normalizeServerUrl('orasec.example.com')).toBe('https://orasec.example.com')
    expect(c.normalizeServerUrl('  https://orasec.example.com/dashboard?x=1 ')).toBe('https://orasec.example.com')
    expect(c.normalizeServerUrl('https://orasec.example.com:8443/')).toBe('https://orasec.example.com:8443')
  })

  it('refuses nonsense, credentials in the address, and plain http in a store build', async () => {
    const c = await load()
    for (const bad of ['', '   ', 'orasec', 'ftp://orasec.example.com', 'https://user:pw@orasec.example.com', 'http://orasec.example.com']) {
      expect(c.normalizeServerUrl(bad), bad).toBeNull()
    }
    expect(c.addressProblem('http://orasec.example.com')).toMatch(/https/)
    expect(c.addressProblem('orasec')).toMatch(/orasec\.example\.com/)
  })

  it('allows plain http only in a development build', async () => {
    const c = await load({ VITE_ALLOW_HTTP: '1' })
    expect(c.normalizeServerUrl('http://10.0.2.2:8180')).toBe('http://10.0.2.2:8180')
  })

  it('the public build knows no server until the person enters one', async () => {
    const c = await load()
    expect(c.DEFAULT_SERVER_URL).toBe('')
    expect(c.SERVER_PRESETS).toEqual([])
    await c.hydrateServerUrl()
    expect(c.hasServer()).toBe(false)
    expect(await c.setServerUrl('orasec.example.com')).toBe('https://orasec.example.com')
    expect(c.hasServer()).toBe(true)
    expect(c.getServerUrl()).toBe('https://orasec.example.com')
    expect(c.getDisplayServerUrl()).toBe('orasec.example.com')
    expect(c.webAppUrl('/orasec/mobile/')).toBe('https://orasec.example.com/orasec/mobile/')
    expect(env.saved).toBe('https://orasec.example.com')
  })

  it('remembers the server between runs', async () => {
    env.saved = 'https://orasec.example.com'
    const c = await load()
    expect(await c.hydrateServerUrl()).toBe('https://orasec.example.com')
    expect(c.hasServer()).toBe(true)
  })

  it('changing the server unlinks the device; the same address does not', async () => {
    env.saved = 'https://one.example.com'
    const c = await load()
    await c.hydrateServerUrl()
    await c.setServerUrl('https://one.example.com')
    expect(session.clearDeviceToken).not.toHaveBeenCalled()
    await c.setServerUrl('https://two.example.com')
    expect(session.clearDeviceToken).toHaveBeenCalledTimes(1)
    expect(await c.setServerUrl('not a server')).toBeNull()
    expect(c.getServerUrl()).toBe('https://two.example.com')
  })

  it('a build can ship its own default server', async () => {
    const c = await load({ VITE_DEFAULT_SERVER_URL: 'https://orasec.example.org' })
    await c.hydrateServerUrl()
    expect(c.hasServer()).toBe(true)
    expect(c.getServerUrl()).toBe('https://orasec.example.org')
  })

  it('a device linked by an older build keeps its server after the update', async () => {
    env.token = 'osm_' + 'a'.repeat(40)
    const c = await load({ VITE_LEGACY_SERVER_URL: 'https://old.example.org' })
    expect(await c.hydrateServerUrl()).toBe('https://old.example.org')
    expect(env.saved).toBe('https://old.example.org')
  })

  it('a device that was never linked, or is in the demo, is asked for the server', async () => {
    let c = await load({ VITE_LEGACY_SERVER_URL: 'https://old.example.org' })
    expect(await c.hydrateServerUrl()).toBe('')
    env.token = 'osm_demo_sample_data_only_000000000000'
    c = await load({ VITE_LEGACY_SERVER_URL: 'https://old.example.org' })
    expect(await c.hydrateServerUrl()).toBe('')
    expect(c.hasServer()).toBe(false)
  })

  it('the browser preview needs no server (it uses the dev proxy)', async () => {
    env.native = false
    const c = await load()
    expect(c.hasServer()).toBe(true)
    expect(c.getServerUrl()).toBe('')
  })

  it('reads development presets and drops broken ones', async () => {
    const c = await load({
      VITE_ALLOW_HTTP: '1',
      VITE_SERVER_PRESETS: JSON.stringify([{ label: 'Test', url: 'http://10.0.2.2:8180', hint: 'emulator' }, { label: 'Bad', url: 'nope' }, { url: 'https://x.example.com' }]),
    })
    expect(c.SERVER_PRESETS).toEqual([{ label: 'Test', url: 'http://10.0.2.2:8180', hint: 'emulator' }])
    expect((await load({ VITE_SERVER_PRESETS: '{broken' })).SERVER_PRESETS).toEqual([])
  })
})

describe('checking that an address is an OraSec server', () => {
  it('accepts a server that says it is OraSec', async () => {
    const c = await load()
    const fetcher = vi.fn().mockResolvedValue(reply(200, { product: 'OraSec', api: 1 }))
    expect(await c.checkServer('orasec.example.com', fetcher)).toEqual({ ok: true, url: 'https://orasec.example.com' })
    expect(fetcher).toHaveBeenCalledWith('https://orasec.example.com/api/v2/orasec/mobile/server/', expect.anything())
  })

  it('accepts an older server that only knows the device API', async () => {
    const c = await load()
    const fetcher = vi.fn().mockResolvedValueOnce(reply(404, {})).mockResolvedValueOnce(reply(401, { error: 'x', code: 'unlinked' }))
    expect(await c.checkServer('orasec.example.com', fetcher)).toEqual({ ok: true, url: 'https://orasec.example.com' })
  })

  it('refuses something that is not OraSec', async () => {
    const c = await load()
    for (const fetcher of [
      vi.fn().mockResolvedValue(reply(200, { product: 'Other' })),
      vi.fn().mockResolvedValue(reply(200, null)),
      vi.fn().mockResolvedValue(reply(500, {})),
      vi.fn().mockResolvedValueOnce(reply(404, {})).mockResolvedValueOnce(reply(404, {})),
      vi.fn().mockResolvedValueOnce(reply(404, {})).mockResolvedValueOnce(reply(401, { code: 'other' })),
    ]) {
      const result = await c.checkServer('example.com', fetcher)
      expect(result.ok).toBe(false)
      if (!result.ok) expect(result.message).toMatch(/OraSec server/)
    }
  })

  it('says so when the mobile app is turned off on the server', async () => {
    const c = await load()
    const fetcher = vi.fn().mockResolvedValue(reply(403, { error: 'The mobile app is turned off on this OraSec server. Ask your administrator.', code: 'plugin_off' }))
    const result = await c.checkServer('orasec.example.com', fetcher)
    expect(result).toEqual({ ok: false, message: 'The mobile app is turned off on this OraSec server. Ask your administrator.' })
  })

  it('says so when the address cannot be reached, and asks nothing for a bad address', async () => {
    const c = await load()
    const down = vi.fn().mockRejectedValue(new TypeError('Failed to fetch'))
    const result = await c.checkServer('orasec.example.com', down)
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.message).toMatch(/reach/)
    const never = vi.fn()
    expect((await c.checkServer('http://orasec.example.com', never)).ok).toBe(false)
    expect(never).not.toHaveBeenCalled()
  })
})
