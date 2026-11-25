import { Capacitor } from '@capacitor/core'

/**
 * Which OraSec server the app talks to.
 *
 * OraSec is self-hosted: the app does not belong to one server. The person types the address of their organisation's
 * OraSec server on the first screen, the app checks that an OraSec server answers there, and keeps the address on
 * the device. It can be changed from the link screen at any time (changing it unlinks the device from the old server).
 *
 * Native: an absolute origin, https only in store builds. A build may ship a default (`VITE_DEFAULT_SERVER_URL`) so
 * an organisation's own build opens straight on its server.
 *
 * Web (the browser preview used for QA, `npm run dev`): '' — same origin through the Vite proxy, which forwards
 * /api to a test instance.
 */
export interface ServerPreset {
  label: string
  url: string
  hint?: string
}

const env = import.meta.env as Record<string, string | undefined>
const STORAGE_KEY = 'orasec.server_url.v1'
const INFO_PATH = '/api/v2/orasec/mobile/server/'
const PROBE_PATH = '/api/v2/orasec/mobile/me/'

/** Plain http is for development only (a test server on the LAN or the emulator). Store builds are https only. */
export function httpAllowed(): boolean {
  return env.VITE_ALLOW_HTTP === '1'
}

export function normalizeServerUrl(input: string, allowHttp = httpAllowed()): string | null {
  const trimmed = (input ?? '').trim()
  if (!trimmed) return null
  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`
  let parsed: URL
  try {
    parsed = new URL(withScheme)
  } catch {
    return null
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null
  if (parsed.protocol === 'http:' && !allowHttp) return null
  if (parsed.username || parsed.password) return null
  if (!parsed.hostname.includes('.') && !parsed.port && parsed.hostname !== 'localhost') return null
  return `${parsed.protocol}//${parsed.host}`
}

/** Why an address was refused, in words for the person typing it. */
export function addressProblem(input: string): string {
  if (/^http:\/\//i.test((input ?? '').trim()) && !httpAllowed()) return 'The address must start with https://'
  return 'Enter the address of your OraSec server, for example orasec.example.com'
}

/** A server every copy of this build starts on (an organisation's own build). Empty in the public app. */
export const DEFAULT_SERVER_URL: string = normalizeServerUrl(env.VITE_DEFAULT_SERVER_URL ?? '') ?? ''

/**
 * The server that builds before 1.3.0 always used. A device that is already linked and has no saved address keeps
 * working after the update. Empty unless the build sets it.
 */
const LEGACY_SERVER_URL: string = normalizeServerUrl(env.VITE_LEGACY_SERVER_URL ?? '') ?? ''

function readPresets(): ServerPreset[] {
  try {
    const raw = JSON.parse(env.VITE_SERVER_PRESETS || '[]') as unknown
    if (!Array.isArray(raw)) return []
    return raw
      .map((p): ServerPreset | null => {
        const o = p as Partial<ServerPreset>
        const url = typeof o.url === 'string' ? normalizeServerUrl(o.url) : null
        return url && typeof o.label === 'string' ? { label: o.label, url, hint: typeof o.hint === 'string' ? o.hint : undefined } : null
      })
      .filter((p): p is ServerPreset => p !== null)
  } catch {
    return []
  }
}

/** Ready-made choices offered under the address field (development builds: test servers). */
export const SERVER_PRESETS: ServerPreset[] = readPresets()

let currentServerUrl: string = DEFAULT_SERVER_URL

/** Base URL for API calls: absolute on native, '' (same origin, via the dev proxy) in the browser preview. */
export function getServerUrl(): string {
  return Capacitor.isNativePlatform() ? currentServerUrl : ''
}

/** True when the app knows which server to talk to. The browser preview always does (its proxy). */
export function hasServer(): boolean {
  return !Capacitor.isNativePlatform() || currentServerUrl !== ''
}

/** The server's host name for display ("orasec.example.com"). */
export function getDisplayServerUrl(): string {
  if (!Capacitor.isNativePlatform()) return 'preview proxy'
  return currentServerUrl.replace(/^https?:\/\//, '')
}

async function readSaved(): Promise<string | null> {
  const { Preferences } = await import('@capacitor/preferences')
  const { value } = await Preferences.get({ key: STORAGE_KEY })
  return value ? normalizeServerUrl(value) : null
}

async function save(url: string): Promise<void> {
  const { Preferences } = await import('@capacitor/preferences')
  if (!url || url === DEFAULT_SERVER_URL) await Preferences.remove({ key: STORAGE_KEY })
  else await Preferences.set({ key: STORAGE_KEY, value: url })
}

/** Load the saved server before anything issues a request. */
export async function hydrateServerUrl(): Promise<string> {
  if (!Capacitor.isNativePlatform()) return currentServerUrl
  try {
    const saved = await readSaved()
    if (saved) {
      currentServerUrl = saved
    } else if (!currentServerUrl && LEGACY_SERVER_URL) {
      const { hydrateDeviceToken } = await import('@/api/session')
      const { isDemoToken } = await import('@/demo/session')
      const token = await hydrateDeviceToken()
      if (token && !isDemoToken(token)) {
        currentServerUrl = LEGACY_SERVER_URL
        await save(LEGACY_SERVER_URL)
      }
    }
  } catch {
    // keep what we have
  }
  return currentServerUrl
}

/** Switch servers ('' forgets the server). The device token belongs to one server, so it is dropped first. */
export async function setServerUrl(url: string): Promise<string | null> {
  const normalized = url === '' ? '' : normalizeServerUrl(url)
  if (normalized === null) return null
  if (normalized === currentServerUrl) return normalized
  try {
    const { clearDeviceToken } = await import('@/api/session')
    await clearDeviceToken()
  } catch {
    // ignore
  }
  try {
    await save(normalized)
  } catch {
    // the address still holds for this run
  }
  currentServerUrl = normalized
  return normalized
}

export type ServerCheck = { ok: true; url: string } | { ok: false; message: string }

/**
 * Is there an OraSec server at this address? Asks the server's public check (no sign-in, no data). A server from
 * before that check existed answers the device API with "not linked", which is proof enough.
 */
export async function checkServer(input: string, fetcher: typeof fetch = fetch): Promise<ServerCheck> {
  const url = normalizeServerUrl(input)
  if (!url) return { ok: false, message: addressProblem(input) }
  const notOraSec = { ok: false as const, message: 'That address did not answer like an OraSec server. Check it with your administrator.' }
  try {
    const info = await fetcher(`${url}${INFO_PATH}`, { headers: { Accept: 'application/json' } })
    if (info.ok) {
      const body = (await info.json().catch(() => null)) as { product?: unknown } | null
      return body?.product === 'OraSec' ? { ok: true, url } : notOraSec
    }
    if (info.status === 403) {
      const body = (await info.json().catch(() => null)) as { code?: unknown; error?: unknown } | null
      if (body?.code === 'plugin_off') {
        return { ok: false, message: typeof body.error === 'string' ? body.error : 'The mobile app is turned off on that server.' }
      }
      return notOraSec
    }
    if (info.status !== 404) return notOraSec
    const probe = await fetcher(`${url}${PROBE_PATH}`, { headers: { Accept: 'application/json' } })
    const body = (await probe.json().catch(() => null)) as { code?: unknown } | null
    return probe.status === 401 && body?.code === 'unlinked' ? { ok: true, url } : notOraSec
  } catch {
    return { ok: false, message: "Can't reach that address. Check the spelling and your connection." }
  }
}

/** The OraSec web app, where people create link codes. */
export function webAppUrl(path = ''): string {
  return `${currentServerUrl}${path}`
}

/** Tests only. */
export function resetServerForTests(url = DEFAULT_SERVER_URL): void {
  currentServerUrl = url
}
