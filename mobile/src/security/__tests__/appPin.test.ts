import { describe, it, expect, beforeEach } from 'vitest'
import {
  MAX_PIN_ATTEMPTS,
  checkPin,
  clearPin,
  hasPin,
  pinProblem,
  remainingAttempts,
  resetPinFailures,
  setPin,
  setSignInNotice,
  takeSignInNotice,
} from '../appPin'

describe('app PIN', () => {
  beforeEach(() => {
    localStorage.clear()
    sessionStorage.clear()
  })

  it('rejects PINs that are not 6 digits, repeated or a straight run', () => {
    expect(pinProblem('12345')).toMatch(/6 digits/)
    expect(pinProblem('12a456')).toMatch(/6 digits/)
    expect(pinProblem('000000')).toMatch(/same digit/)
    expect(pinProblem('123456')).toMatch(/run of numbers/)
    expect(pinProblem('987654')).toMatch(/run of numbers/)
    expect(pinProblem('482913')).toBeNull()
  })

  it('stores only a salted hash, for one user', async () => {
    await setPin('user-1', '482913')
    const raw = localStorage.getItem('orasec.app_pin.v1') ?? ''
    expect(raw).not.toContain('482913')
    expect(JSON.parse(raw).iterations).toBeGreaterThanOrEqual(100_000)
    expect(hasPin('user-1')).toBe(true)
    expect(hasPin('user-2')).toBe(false)
    expect(hasPin(null)).toBe(false)
  })

  it('accepts the right PIN and counts wrong ones across checks', async () => {
    await setPin('u', '482913')
    expect(await checkPin('u', '482913')).toEqual({ ok: true, remaining: MAX_PIN_ATTEMPTS })
    expect(await checkPin('u', '111112')).toEqual({ ok: false, remaining: 4 })
    expect(remainingAttempts('u')).toBe(4)
    // a correct PIN resets the count
    expect((await checkPin('u', '482913')).ok).toBe(true)
    expect(remainingAttempts('u')).toBe(MAX_PIN_ATTEMPTS)
  })

  it('forgets the PIN on the fifth wrong entry', async () => {
    await setPin('u', '482913')
    for (let i = 1; i < MAX_PIN_ATTEMPTS; i++) {
      expect((await checkPin('u', '000001')).remaining).toBe(MAX_PIN_ATTEMPTS - i)
    }
    expect(await checkPin('u', '000001')).toEqual({ ok: false, remaining: 0 })
    expect(hasPin('u')).toBe(false)
  })

  it('a PIN for someone else never unlocks', async () => {
    await setPin('owner', '482913')
    expect(await checkPin('intruder', '482913')).toEqual({ ok: false, remaining: 0 })
    expect(hasPin('owner')).toBe(true)
  })

  it('Face ID success resets the wrong-PIN count; clearPin forgets it', async () => {
    await setPin('u', '482913')
    await checkPin('u', '000001')
    resetPinFailures('u')
    expect(remainingAttempts('u')).toBe(MAX_PIN_ATTEMPTS)
    clearPin()
    expect(hasPin('u')).toBe(false)
  })

  it('passes a one-off notice to the sign-in screen', () => {
    setSignInNotice('Too many wrong PIN attempts.')
    expect(takeSignInNotice()).toBe('Too many wrong PIN attempts.')
    expect(takeSignInNotice()).toBeNull()
  })
})
