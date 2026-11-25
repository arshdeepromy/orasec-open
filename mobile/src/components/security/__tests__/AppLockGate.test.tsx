import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

// Ported from the publisher's invoicing app,
// adapted to OraSec's optional app lock (Settings → App lock).

const verify = vi.fn<() => Promise<boolean>>()
const setEnabled = vi.fn()
const signOut = vi.fn(async () => {})
let authState: Record<string, unknown> = {}
let bio: { isEnabled: boolean; isAvailable: boolean; label?: string } = { isEnabled: false, isAvailable: true }
let native = true

vi.mock('@capacitor/core', () => ({
  Capacitor: {
    isNativePlatform: () => native,
    isPluginAvailable: () => false,
    getPlatform: () => (native ? 'android' : 'web'),
  },
  registerPlugin: () => ({}),
}))
vi.mock('@capacitor/app', () => ({
  App: { addListener: vi.fn(async () => ({ remove: vi.fn() })), minimizeApp: vi.fn() },
}))
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ ...authState, signOut }),
}))
vi.mock('@/contexts/BiometricContext', () => ({
  useBiometric: () => ({ label: 'Face ID or fingerprint', ...bio, verify, setEnabled, isVerifying: false }),
}))

import { _resetAppLockGate, AppLockGate } from '../AppLockGate'
import { getAppLockSettings, saveAppLockSettings } from '@/security/appLock'
import { hasPin, setPin, takeSignInNotice } from '@/security/appPin'

const USER = { id: 7, email: 'owner@example.com' }

function signedIn() {
  authState = { status: 'signedIn', user: USER }
}

async function typePin(pin: string) {
  for (const d of pin) fireEvent.click(screen.getByRole('button', { name: d }))
  await act(async () => {
    await new Promise((r) => setTimeout(r, 120))
  })
}

const tree = () => (
  <AppLockGate>
    <p>secret content</p>
  </AppLockGate>
)

/** Cold start signed out, then a password / passkey sign-in in this launch. */
function freshSignIn() {
  authState = { status: 'signedOut', user: null }
  const view = render(tree())
  signedIn()
  view.rerender(tree())
  return view
}

async function lockOnWithPin(pin = '482913') {
  await setPin('7', pin)
  saveAppLockSettings({ userId: '7', enabled: true, timeoutMs: 60_000 })
}

describe('AppLockGate', () => {
  beforeEach(() => {
    localStorage.clear()
    sessionStorage.clear()
    verify.mockReset()
    setEnabled.mockReset()
    signOut.mockClear()
    bio = { isEnabled: false, isAvailable: true }
    native = true
    signedIn()
    _resetAppLockGate()
  })

  it('offers a PIN on the first sign-in; "Not now" turns the lock off for this person', async () => {
    freshSignIn()
    expect(screen.getByTestId('pin-setup-intro')).toBeTruthy()
    fireEvent.click(screen.getByTestId('pin-setup-skip'))
    await waitFor(() => expect(screen.queryByTestId('pin-setup-intro')).toBeNull())
    expect(getAppLockSettings('7')?.enabled).toBe(false)
    expect(screen.getByText('secret content')).toBeTruthy()
  })

  it('creates and confirms a 6-digit PIN, then offers biometrics and turns the lock on', async () => {
    freshSignIn()
    fireEvent.click(screen.getByTestId('pin-setup-start'))
    expect(screen.getByText('Create a 6-digit PIN')).toBeTruthy()

    await typePin('123456')
    await waitFor(() => expect(screen.getByRole('alert').textContent).toMatch(/run of numbers/))

    await typePin('482913')
    await waitFor(() => expect(screen.getByText('Confirm your PIN')).toBeTruthy())
    await typePin('482913')

    await waitFor(() => expect(screen.getByTestId('pin-setup-biometric')).toBeTruthy())
    expect(hasPin('7')).toBe(true)
    verify.mockResolvedValue(true)
    fireEvent.click(screen.getByTestId('pin-setup-biometric-on'))
    await waitFor(() => expect(setEnabled).toHaveBeenCalledWith(true))
    await waitFor(() => expect(getAppLockSettings('7')?.enabled).toBe(true))
  })

  it('locks a restored session (lock on) and unlocks with the PIN', async () => {
    await lockOnWithPin()
    render(tree())
    await waitFor(() => expect(screen.getByTestId('app-lock')).toBeTruthy())
    expect(screen.getByTestId('app-lock').getAttribute('data-sensitive-screen')).toBe('pin')
    await typePin('482913')
    await waitFor(() => expect(screen.queryByTestId('app-lock')).toBeNull())
  })

  it('does not lock a restored session when the person turned the lock off', () => {
    saveAppLockSettings({ userId: '7', enabled: false, timeoutMs: 60_000 })
    render(tree())
    expect(screen.queryByTestId('app-lock')).toBeNull()
    expect(screen.queryByTestId('pin-setup-intro')).toBeNull()
  })

  it('signs out after five wrong PINs and forgets the PIN', async () => {
    await lockOnWithPin()
    render(tree())
    await waitFor(() => expect(screen.getByTestId('app-lock')).toBeTruthy())
    // Each wrong PIN runs PBKDF2; give it time on a busy build machine.
    for (let left = 4; left >= 1; left--) {
      await typePin('000001')
      await waitFor(() => expect(screen.getByRole('alert').textContent).toMatch(new RegExp(`Wrong PIN\\. ${left} attempt`)), { timeout: 10000 })
    }
    await typePin('000001')
    await waitFor(() => expect(signOut).toHaveBeenCalled(), { timeout: 10000 })
    expect(hasPin('7')).toBe(false)
    expect(takeSignInNotice()).toMatch(/Too many wrong PIN attempts/)
  })

  it('Forgot PIN signs out and forgets the PIN', async () => {
    await lockOnWithPin()
    render(tree())
    await waitFor(() => expect(screen.getByTestId('app-lock')).toBeTruthy())
    fireEvent.click(screen.getByTestId('pin-forgot'))
    await waitFor(() => expect(signOut).toHaveBeenCalled())
    expect(hasPin('7')).toBe(false)
  })

  it('signs out a restored session whose lock is on but whose PIN is gone (house rule)', async () => {
    saveAppLockSettings({ userId: '7', enabled: true, timeoutMs: 60_000 })
    render(tree())
    expect(screen.queryByTestId('pin-setup')).toBeNull()
    expect(screen.getByTestId('app-lock-cover')).toBeTruthy()
    await waitFor(() => expect(signOut).toHaveBeenCalled())
    expect(takeSignInNotice()).toMatch(/link this phone again/i)
  })

  it('offers biometrics on the lock screen when on; a cancel leaves the PIN pad', async () => {
    await lockOnWithPin()
    bio = { isEnabled: true, isAvailable: true, label: 'Touch ID' }
    verify.mockResolvedValueOnce(false).mockResolvedValueOnce(true)
    render(tree())
    await waitFor(() => expect(verify).toHaveBeenCalledTimes(1))
    expect(screen.getByTestId('app-lock')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Unlock with Touch ID' }))
    await waitFor(() => expect(screen.queryByTestId('app-lock')).toBeNull())
    expect(signOut).not.toHaveBeenCalled()
  })

  it('does not lock again when remounted later in the same launch', async () => {
    await lockOnWithPin()
    const first = render(tree())
    await waitFor(() => expect(screen.getByTestId('app-lock')).toBeTruthy())
    await typePin('482913')
    await waitFor(() => expect(screen.queryByTestId('app-lock')).toBeNull())
    first.unmount()
    render(tree())
    expect(screen.queryByTestId('app-lock')).toBeNull()
  })

  it('takes the PIN from a hardware keyboard', async () => {
    await lockOnWithPin()
    render(tree())
    await waitFor(() => expect(screen.getByTestId('app-lock')).toBeTruthy())
    for (const k of '4829') fireEvent.keyDown(window, { key: k })
    fireEvent.keyDown(window, { key: '7' })
    fireEvent.keyDown(window, { key: 'Backspace' })
    for (const k of '13') fireEvent.keyDown(window, { key: k })
    await act(async () => {
      await new Promise((r) => setTimeout(r, 150))
    })
    await waitFor(() => expect(screen.queryByTestId('app-lock')).toBeNull())
  })

  it('never shows in the browser preview', async () => {
    native = false
    await lockOnWithPin()
    render(tree())
    expect(screen.queryByTestId('app-lock')).toBeNull()
    expect(screen.queryByTestId('pin-setup-intro')).toBeNull()
  })
})

