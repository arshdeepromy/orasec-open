/**
 * App PIN — the 6-digit code that unlocks the app on this device.
 *
 * Offered to every person the first time they sign in to the installed app
 * (Settings → App lock turns it on or off later). From then on the app opens
 * with the PIN (or Face ID / fingerprint, if they turn that on) instead of the
 * email and password, for as long as the signed-in session lasts.
 *
 * Ported from the publisher's invoicing app.
 *
 * The PIN never leaves the device and is not a server credential: it unlocks
 * the session already stored on this phone. Only a salted PBKDF2-SHA-256 hash
 * is kept, with the owner's user id so a different person signing in on the
 * same phone does not inherit it. Five wrong entries sign the person out and
 * forget the PIN; they then sign in with their password or passkey and set a
 * new one.
 */

import { mirrorLockValue } from '@/security/lockStore'

export const PIN_LENGTH = 6
export const MAX_PIN_ATTEMPTS = 5
const STORAGE_KEY = 'orasec.app_pin.v1'
const ITERATIONS = 210_000
/** Message the sign-in screen shows after a PIN sign-out (read once). */
const FLASH_KEY = 'orasec.app_pin.flash'

interface StoredPin {
  userId: string
  salt: string
  hash: string
  iterations: number
  failures: number
}

function read(): StoredPin | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return null
    const parsed = JSON.parse(raw) as StoredPin
    return parsed && typeof parsed.hash === 'string' && typeof parsed.userId === 'string'
      ? parsed
      : null
  } catch {
    return null
  }
}

function write(record: StoredPin | null) {
  try {
    if (record) localStorage.setItem(STORAGE_KEY, JSON.stringify(record))
    else localStorage.removeItem(STORAGE_KEY)
  } catch {
    // storage unavailable — the PIN simply isn't remembered
  }
  // The Keychain / Keystore vault is the real store (security/lockStore.ts).
  mirrorLockValue(STORAGE_KEY, record ? JSON.stringify(record) : null)
}

function toB64(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s)
}

function fromB64(value: string): Uint8Array {
  const bin = atob(value)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

async function derive(pin: string, salt: Uint8Array, iterations: number): Promise<string> {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pin), 'PBKDF2', false, [
    'deriveBits',
  ])
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: salt as BufferSource, iterations },
    key,
    256,
  )
  return toB64(new Uint8Array(bits))
}

/** Constant-time string comparison. */
function same(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}

/** True when `userId` has a PIN on this device. */
export function hasPin(userId: string | null | undefined): boolean {
  if (!userId) return false
  return read()?.userId === userId
}

/** Why a new PIN is not acceptable, or null when it is. */
export function pinProblem(pin: string): string | null {
  if (!new RegExp(`^\\d{${PIN_LENGTH}}$`).test(pin)) return `Your PIN must be ${PIN_LENGTH} digits.`
  if (/^(\d)\1+$/.test(pin)) return 'Choose a PIN that isn\u2019t the same digit repeated.'
  const digits = pin.split('').map(Number)
  const step = digits[1] - digits[0]
  if ((step === 1 || step === -1) && digits.every((d, i) => i === 0 || d - digits[i - 1] === step)) {
    return 'Choose a PIN that isn\u2019t a run of numbers like 123456.'
  }
  return null
}

/** Store a new PIN for `userId` (replacing any PIN on this device). */
export async function setPin(userId: string, pin: string): Promise<void> {
  const problem = pinProblem(pin)
  if (problem) throw new Error(problem)
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const hash = await derive(pin, salt, ITERATIONS)
  write({ userId, salt: toB64(salt), hash, iterations: ITERATIONS, failures: 0 })
}

export interface PinCheck {
  ok: boolean
  /** Attempts left before sign-out (0 = signed out, PIN forgotten). */
  remaining: number
}

/**
 * Check a PIN. Wrong entries are counted on the device (they survive an app
 * restart, so closing the app does not reset the count); the fifth wrong one
 * forgets the PIN and returns `remaining: 0` — the caller signs out.
 */
export async function checkPin(userId: string, pin: string): Promise<PinCheck> {
  const record = read()
  if (!record || record.userId !== userId) return { ok: false, remaining: 0 }
  const hash = await derive(pin, fromB64(record.salt), record.iterations)
  if (same(hash, record.hash)) {
    if (record.failures) write({ ...record, failures: 0 })
    return { ok: true, remaining: MAX_PIN_ATTEMPTS }
  }
  const failures = record.failures + 1
  if (failures >= MAX_PIN_ATTEMPTS) {
    write(null)
    return { ok: false, remaining: 0 }
  }
  write({ ...record, failures })
  return { ok: false, remaining: MAX_PIN_ATTEMPTS - failures }
}

/** Attempts left for the stored PIN (for the lock screen after a restart). */
export function remainingAttempts(userId: string | null | undefined): number {
  const record = read()
  if (!record || !userId || record.userId !== userId) return MAX_PIN_ATTEMPTS
  return Math.max(0, MAX_PIN_ATTEMPTS - record.failures)
}

/** A correct Face ID / fingerprint unlock also clears the wrong-PIN count. */
export function resetPinFailures(userId: string | null | undefined) {
  const record = read()
  if (record && userId && record.userId === userId && record.failures) write({ ...record, failures: 0 })
}

/** Forget the PIN on this device ("Forgot PIN?", too many wrong entries). */
export function clearPin() {
  write(null)
}

/** Leave a one-off message for the sign-in screen. */
export function setSignInNotice(message: string) {
  try {
    sessionStorage.setItem(FLASH_KEY, message)
  } catch {
    // ignore
  }
}

/** Read (and clear) the one-off sign-in screen message. */
export function takeSignInNotice(): string | null {
  try {
    const message = sessionStorage.getItem(FLASH_KEY)
    if (message) sessionStorage.removeItem(FLASH_KEY)
    return message
  } catch {
    return null
  }
}
