import { ApiError } from '@/api/http'
import { orasec, type PushState } from '@/api/orasec'
import { isDemoSession } from '@/demo/session'
import { pushPermission, pushSupported, requestPushToken } from '@/native/push'

/**
 * Notifications on this phone: switching them on and off, and keeping the server's copy of the phone's address
 * fresh. The choice is remembered per install; the four kinds of notification are saved to the account
 * (orasec.pushSettings), so they are the same on every phone of one person.
 */
const OPT_IN_KEY = 'orasec.push.optin.v1'

/** Screens the app may open from a notification. Anything else in a notification is ignored. */
const TAP_PATHS = new Set(['/', '/vulns', '/attacks', '/governance', '/my-work', '/settings/notifications'])

export type TurnOnResult =
  | { ok: true; state: PushState }
  | { ok: false; reason: 'unsupported' | 'denied' | 'unavailable' | 'error'; message: string }

export function isPushOptedIn(): boolean {
  try {
    return globalThis.localStorage?.getItem(OPT_IN_KEY) === '1'
  } catch {
    return false
  }
}

export function setPushOptIn(on: boolean): void {
  try {
    if (on) globalThis.localStorage?.setItem(OPT_IN_KEY, '1')
    else globalThis.localStorage?.removeItem(OPT_IN_KEY)
  } catch {
    // ignore
  }
}

export function safeTapPath(path: string | undefined): string | null {
  return path && TAP_PATHS.has(path) ? path : null
}

/** Ask the phone for permission, then give its address to OraSec. */
export async function turnOnPush(): Promise<TurnOnResult> {
  if (isDemoSession()) return { ok: false, reason: 'unavailable', message: 'Notifications need a phone that is linked to OraSec.' }
  if (!pushSupported()) return { ok: false, reason: 'unsupported', message: 'Notifications work in the installed OraSec app.' }
  let token: string | null
  try {
    token = await requestPushToken(true)
  } catch {
    token = null
  }
  if (!token) {
    const permission = await pushPermission()
    if (permission === 'denied') {
      return { ok: false, reason: 'denied', message: 'Notifications are switched off for OraSec in this phone’s settings. Turn them on there, then try again.' }
    }
    if (permission !== 'granted') {
      // The person answered "Don't allow" and the phone may still ask again (Android after the first "no").
      return { ok: false, reason: 'denied', message: 'Notifications stay off because you did not allow them. Tap the switch again if you change your mind.' }
    }
    return { ok: false, reason: 'error', message: 'This phone did not give a notification address. Check the connection and try again.' }
  }
  try {
    const state = await orasec.pushRegister(token)
    setPushOptIn(true)
    return { ok: true, state }
  } catch (error) {
    const missing = error instanceof ApiError && error.status === 404
    return missing
      ? { ok: false, reason: 'unavailable', message: 'Your OraSec server does not send notifications yet.' }
      : { ok: false, reason: 'error', message: error instanceof Error ? error.message : 'Could not switch notifications on.' }
  }
}

export async function turnOffPush(): Promise<PushState | null> {
  setPushOptIn(false)
  try {
    return await orasec.pushUnregister()
  } catch {
    return null // offline: the phone is forgotten when it signs out or the address stops working
  }
}

/** On app start: send the phone's current address again (Google and Apple change it now and then). Never asks. */
export async function refreshPushRegistration(): Promise<void> {
  if (!isPushOptedIn() || isDemoSession() || !pushSupported()) return
  try {
    if ((await pushPermission()) !== 'granted') return
    const token = await requestPushToken(false)
    if (token) await orasec.pushRegister(token)
  } catch {
    // Not reachable right now: tried again on the next start.
  }
}
