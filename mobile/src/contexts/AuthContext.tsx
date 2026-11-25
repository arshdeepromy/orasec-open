import { Capacitor } from '@capacitor/core'
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'

import { ApiError } from '@/api/http'
import { orasec, type Device, type User } from '@/api/orasec'
import { clearDeviceToken, getDeviceToken, hydrateDeviceToken, onDeviceRejected, setDeviceToken } from '@/api/session'
import { DEMO_TOKEN } from '@/demo/session'
import { setPushOptIn } from '@/notifications/pushController'
import { setPlugins } from '@/plugins/pluginState'
import { APP_VERSION } from '@/utils/appVersion'

/**
 * Whether this phone is linked to OraSec, and as whom.
 *
 * There are no passwords in the app: a person who is already signed in to OraSec on the web (behind Cloudflare
 * Access) creates a one-time link code (Profile menu → Mobile app) and enters it here. The server answers with a
 * device token, kept in the Keychain / Keystore vault. Signing out revokes it on the server; revoking it on the web
 * signs the phone out on its next request.
 */
export type AuthStatus = 'loading' | 'signedOut' | 'signedIn'

type AuthContextValue = {
  status: AuthStatus
  user: User | null
  device: Device | null
  /** True when the last check failed because the phone is offline (the cached user is still shown). */
  offline: boolean
  link: (code: string) => Promise<void>
  /** Open the demo: bundled sample data, no server (anyone can try the app). */
  startDemo: () => Promise<void>
  signOut: () => Promise<void>
  refresh: () => Promise<void>
  /** Set when the server signed the phone out (revoked on the web, or unused for 60 days). */
  signedOutReason: string | null
}

const AuthContext = createContext<AuthContextValue | null>(null)
const USER_SNAPSHOT_KEY = 'orasec.user.v1'

type Snapshot = { user: User; device: Device }

function readSnapshot(): Snapshot | null {
  try {
    const raw = globalThis.localStorage?.getItem(USER_SNAPSHOT_KEY)
    return raw ? (JSON.parse(raw) as Snapshot) : null
  } catch {
    return null
  }
}

function writeSnapshot(s: Snapshot | null): void {
  try {
    if (s) globalThis.localStorage?.setItem(USER_SNAPSHOT_KEY, JSON.stringify(s))
    else globalThis.localStorage?.removeItem(USER_SNAPSHOT_KEY)
  } catch {
    // ignore
  }
}

export function deviceName(): string {
  const platform = Capacitor.getPlatform()
  const ua = typeof navigator !== 'undefined' ? navigator.userAgent : ''
  if (platform === 'ios') return /iPad/.test(ua) ? 'iPad' : 'iPhone'
  if (platform === 'android') {
    const m = /Android [\d.]+; ([^;)]+?)(?: Build|\))/.exec(ua)
    return m ? m[1].trim().slice(0, 60) : 'Android phone'
  }
  return 'Browser preview'
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<AuthStatus>('loading')
  const [user, setUser] = useState<User | null>(null)
  const [device, setDevice] = useState<Device | null>(null)
  const [offline, setOffline] = useState(false)
  const [signedOutReason, setSignedOutReason] = useState<string | null>(null)

  const applySignedOut = useCallback((reason: string | null) => {
    writeSnapshot(null)
    setPushOptIn(false) // the server forgets the phone's notification address when it is signed out
    setPlugins(null)
    setUser(null)
    setDevice(null)
    setSignedOutReason(reason)
    setStatus('signedOut')
  }, [])

  const refresh = useCallback(async () => {
    const token = await hydrateDeviceToken()
    if (!token) {
      applySignedOut(null)
      return
    }
    try {
      const me = await orasec.me()
      writeSnapshot({ user: me.user, device: me.device })
      setPlugins(me.plugins ?? null)
      setUser(me.user)
      setDevice(me.device)
      setOffline(false)
      setStatus('signedIn')
    } catch (error) {
      if (error instanceof ApiError && (error.status === 401 || error.status === 403)) {
        await clearDeviceToken()
        applySignedOut(error.message)
        return
      }
      // Offline or server trouble: keep working with the last known user.
      const snap = readSnapshot()
      if (snap) {
        setUser(snap.user)
        setDevice(snap.device)
        setOffline(true)
        setStatus('signedIn')
      } else {
        applySignedOut(null)
      }
    }
  }, [applySignedOut])

  useEffect(() => {
    void refresh()
  }, [refresh])

  useEffect(
    () =>
      onDeviceRejected(() => {
        applySignedOut('This phone was signed out of OraSec. Link it again to continue.')
      }),
    [applySignedOut],
  )

  const link = useCallback(async (code: string) => {
    const result = await orasec.link(code, deviceName(), Capacitor.getPlatform(), APP_VERSION)
    await setDeviceToken(result.token)
    writeSnapshot({ user: result.user, device: result.device })
    setUser(result.user)
    setDevice(result.device)
    setSignedOutReason(null)
    setOffline(false)
    setStatus('signedIn')
    // The link answer has no plugin list; ask for it without holding the person up.
    void orasec
      .me()
      .then((me) => setPlugins(me.plugins ?? null))
      .catch(() => undefined)
  }, [])

  const startDemo = useCallback(async () => {
    await setDeviceToken(DEMO_TOKEN)
    const me = await orasec.me() // answered locally in demo mode
    writeSnapshot({ user: me.user, device: me.device })
    setPlugins(me.plugins ?? null)
    setUser(me.user)
    setDevice(me.device)
    setSignedOutReason(null)
    setOffline(false)
    setStatus('signedIn')
  }, [])

  const signOut = useCallback(async () => {
    if (getDeviceToken()) {
      try {
        await orasec.logout()
      } catch {
        // Offline: the token is still dropped here; it can be revoked from the web.
      }
    }
    await clearDeviceToken()
    applySignedOut(null)
  }, [applySignedOut])

  const value = useMemo(
    () => ({ status, user, device, offline, link, startDemo, signOut, refresh, signedOutReason }),
    [status, user, device, offline, link, startDemo, signOut, refresh, signedOutReason],
  )
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider')
  return ctx
}

