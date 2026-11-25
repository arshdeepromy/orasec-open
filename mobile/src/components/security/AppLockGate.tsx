import { Capacitor } from '@capacitor/core'
import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'

import { BrandMark } from '@/components/BrandMark'
import { useAuth } from '@/contexts/AuthContext'
import { useBiometric } from '@/contexts/BiometricContext'
import { useBackButtonClose } from '@/hooks/useBackButtonClose'
import { saveAppLockSettings, updateAppLockSettings, useAppLockSettings, DEFAULT_RELOCK_MS } from '@/security/appLock'
import {
  checkPin,
  clearPin,
  hasPin,
  MAX_PIN_ATTEMPTS,
  pinProblem,
  remainingAttempts,
  resetPinFailures,
  setPin,
  setSignInNotice,
} from '@/security/appPin'
import { GENERIC_BIOMETRIC_LABEL } from '@/security/biometricLabel'

import { PinLink, PinPad } from './PinPad'

import './security.css'

/**
 * Module-level on purpose: the gate can be remounted (sign-out / sign-in swap
 * the tree), and a remount must not be mistaken for a cold start — that would
 * re-lock the app straight after a password sign-in.
 */
let coldStartHandled = false
/** Test helper. */
export function _resetAppLockGate() {
  coldStartHandled = false
}

function minimize() {
  import('@capacitor/app')
    .then(({ App }) => App.minimizeApp())
    .catch(() => {})
}

/**
 * The app lock: a 6-digit PIN, plus Face ID / fingerprint if the person turns
 * it on. Ported from the publisher's invoicing app (components/security/AppLockGate.tsx);
 * in OraSec it is offered on the first sign-in and can be turned off in
 * Settings → App lock (where the relock timeout is chosen too).
 *
 * - First sign-in on the device: "Protect OraSec with a PIN?" — create a PIN
 *   (then offered Face ID / fingerprint) or "Not now".
 * - Lock on: every cold start with a remembered session, and every return
 *   after the chosen time in the background, covers the app until the PIN
 *   (or biometrics) is entered. The screens stay mounted underneath, so
 *   unlocking returns the person exactly where they were.
 * - A RESTORED session whose lock is on but whose PIN is gone from the device
 *   is signed out (choosing a new PIN must follow a password / passkey
 *   sign-in, never only the phone in hand) — house rule.
 * - Five wrong PINs, or "Forgot PIN?", sign the person out and forget the PIN.
 *
 * Native app only — the browser preview has no lock.
 */
export function AppLockGate({ children }: { children: ReactNode }) {
  const { user, status, signOut: authSignOut } = useAuth()
  const biometric = useBiometric()
  const userId = user ? String(user.id) : null
  const eligible = Capacitor.isNativePlatform() && status === 'signedIn' && !!userId
  const settings = useAppLockSettings(userId)

  // hasPin() reads storage; bump after setting / clearing to re-read.
  const [pinVersion, setPinVersion] = useState(0)
  const pinSet = eligible && pinVersion >= 0 && hasPin(userId)
  const lockOn = eligible && settings?.enabled === true
  const lockable = lockOn && pinSet
  const bioOn = lockable && biometric.isEnabled && biometric.isAvailable
  const bioLabel = biometric.label || GENERIC_BIOMETRIC_LABEL
  const relockMs = settings?.timeoutMs ?? DEFAULT_RELOCK_MS

  const [locked, setLocked] = useState(false)
  const [coldChecked, setColdChecked] = useState(coldStartHandled)
  const [signingOut, setSigningOut] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const backgroundedAt = useRef<number | null>(null)
  const prompted = useRef(false)

  // Signing out drops the lock.
  useEffect(() => {
    if (!eligible) {
      setLocked(false)
      setError(null)
      setSigningOut(false)
    }
  }, [eligible])

  const signOut = useCallback(
    async (notice?: string, forgetPin = false) => {
      if (forgetPin) clearPin()
      if (notice) setSignInNotice(notice)
      setLocked(false)
      setPinVersion((v) => v + 1)
      await authSignOut()
    },
    [authSignOut],
  )

  // Cold start: lock a RESTORED session as soon as it turns out to be signed
  // in. Signing in a moment later must not ask for the PIN as well.
  useEffect(() => {
    if (status === 'loading' || coldStartHandled) return
    coldStartHandled = true
    setColdChecked(true)
    if (status !== 'signedIn' || !Capacitor.isNativePlatform()) return
    if (lockable) {
      setLocked(true)
    } else if (lockOn) {
      setSigningOut(true)
      void signOut('For your security, link this phone again, then choose your PIN.')
    }
  }, [status, lockable, lockOn, signOut])

  // Re-lock after the chosen time in the background.
  useEffect(() => {
    if (!lockable) return
    let remove: (() => void) | undefined
    let cancelled = false
    import('@capacitor/app')
      .then(({ App }) =>
        App.addListener('appStateChange', ({ isActive }) => {
          if (!isActive) {
            backgroundedAt.current = Date.now()
            return
          }
          const since = backgroundedAt.current
          backgroundedAt.current = null
          if (since !== null && Date.now() - since >= relockMs) {
            prompted.current = false
            setError(null)
            setLocked(true)
          }
        }),
      )
      .then((handle) => {
        if (cancelled) void handle.remove()
        else remove = () => void handle.remove()
      })
      .catch(() => {})
    return () => {
      cancelled = true
      remove?.()
    }
  }, [lockable, relockMs])

  const unlock = useCallback(() => {
    setError(null)
    setLocked(false)
  }, [])

  const tryBiometric = useCallback(async () => {
    if (busy) return
    setBusy(true)
    const ok = await biometric.verify()
    setBusy(false)
    if (ok) {
      resetPinFailures(userId)
      unlock()
    }
    // A cancelled / failed biometric check just leaves the PIN pad up; it
    // never counts toward the PIN attempts (the OS limits biometric retries).
  }, [busy, biometric, userId, unlock])

  // Offer Face ID / fingerprint straight away each time the lock comes up.
  useEffect(() => {
    if (locked && bioOn && !prompted.current) {
      prompted.current = true
      void tryBiometric()
    }
    if (!locked) prompted.current = false
  }, [locked, bioOn, tryBiometric])

  const submitPin = useCallback(
    async (pin: string) => {
      if (!userId) return
      setBusy(true)
      const result = await checkPin(userId, pin)
      setBusy(false)
      if (result.ok) {
        unlock()
        return
      }
      if (result.remaining <= 0) {
        await signOut('Too many wrong PIN attempts. This phone was signed out: create a new link code in OraSec to link it again.')
        return
      }
      setError(`Wrong PIN. ${result.remaining} attempt${result.remaining === 1 ? '' : 's'} left before you need to link this phone again.`)
    },
    [userId, unlock, signOut],
  )

  // PIN setup: on the first sign-in on this device (no decision yet), or after
  // signing in again when the lock is on but the PIN was forgotten.
  const needsSetup = eligible && coldChecked && !locked && !signingOut && (settings === null || (settings.enabled && !pinSet))

  // Android back on the lock / setup screens leaves the app; it must not
  // reveal what's underneath.
  useBackButtonClose((locked && lockable) || needsSetup, minimize)

  const showLock = locked && lockable
  const remaining = userId ? remainingAttempts(userId) : MAX_PIN_ATTEMPTS
  const coldPending = eligible && !coldChecked

  // While a lock or the PIN setup covers the app, the screens underneath stay
  // mounted (so a relock doesn't lose work) but are hidden from screen readers
  // and can't take focus. display:contents keeps the layout untouched.
  const covered = showLock || signingOut || coldPending || Boolean(needsSetup && userId)

  return (
    <>
      <div style={{ display: 'contents' }} aria-hidden={covered || undefined} inert={covered || undefined}>
        {children}
      </div>
      {(signingOut || coldPending) && <div className="lock-screen" data-testid="app-lock-cover" data-sensitive-screen="lock" aria-hidden="true" />}
      {showLock && (
        <PinPad
          testId="app-lock"
          title="Enter your PIN"
          subtitle={user?.email}
          error={error ?? (remaining < MAX_PIN_ATTEMPTS ? `${remaining} attempts left` : null)}
          busy={busy}
          onComplete={submitPin}
          biometric={bioOn ? { label: `Unlock with ${bioLabel}`, onPress: () => void tryBiometric() } : undefined}
          footer={
            <PinLink testId="pin-forgot" onClick={() => void signOut('Create a new link code in OraSec to link this phone again, then choose a new PIN.', true)}>
              Forgot PIN?
            </PinLink>
          }
        />
      )}
      {needsSetup && userId && (
        <PinSetup
          userId={userId}
          required={settings?.enabled === true}
          offerBiometric={biometric.isAvailable && !biometric.isEnabled}
          biometricLabel={bioLabel}
          verifyBiometric={biometric.verify}
          enableBiometric={() => biometric.setEnabled(true)}
          onDone={() => {
            updateAppLockSettings(userId, { enabled: true })
            setPinVersion((v) => v + 1)
          }}
          onSkip={() => {
            clearPin()
            biometric.setEnabled(false)
            saveAppLockSettings({ userId, enabled: false, timeoutMs: settings?.timeoutMs ?? DEFAULT_RELOCK_MS })
            setPinVersion((v) => v + 1)
          }}
        />
      )}
    </>
  )
}

type SetupStep = 'intro' | 'create' | 'confirm' | 'biometric'

/** Choose the PIN (then Face ID / fingerprint), or skip. */
export function PinSetup({
  userId,
  required = false,
  offerBiometric,
  biometricLabel = GENERIC_BIOMETRIC_LABEL,
  verifyBiometric,
  enableBiometric,
  onDone,
  onSkip,
}: {
  userId: string
  /** The lock was on (PIN forgotten): skip turns the lock off. */
  required?: boolean
  offerBiometric: boolean
  biometricLabel?: string
  verifyBiometric: () => Promise<boolean>
  enableBiometric: () => void
  onDone: () => void
  onSkip?: () => void
}) {
  const [step, setStep] = useState<SetupStep>(required ? 'create' : 'intro')
  const [first, setFirst] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [pinSaved, setPinSaved] = useState(false)

  const onFirst = useCallback((pin: string) => {
    const problem = pinProblem(pin)
    if (problem) {
      setError(problem)
      return
    }
    setError(null)
    setFirst(pin)
    setStep('confirm')
  }, [])

  const onConfirm = useCallback(
    async (pin: string) => {
      if (pin !== first) {
        setFirst('')
        setStep('create')
        setError('Those PINs didn’t match. Choose your PIN again.')
        return
      }
      setBusy(true)
      try {
        await setPin(userId, pin)
      } catch (err) {
        setBusy(false)
        setStep('create')
        setError(err instanceof Error ? err.message : 'Couldn’t save your PIN.')
        return
      }
      setBusy(false)
      setPinSaved(true)
      if (offerBiometric) setStep('biometric')
      else onDone()
    },
    [first, userId, offerBiometric, onDone],
  )

  if (step === 'intro') {
    return (
      <div className="lock-screen" role="dialog" aria-modal="true" aria-label="Protect OraSec with a PIN" data-testid="pin-setup-intro" data-sensitive-screen="lock">
        <BrandMark size={64} className="lock-mark" />
        <h1 className="lock-title">Protect OraSec with a PIN?</h1>
        <p className="lock-sub">
          Your security data stays behind a 6-digit PIN{offerBiometric ? ` or ${biometricLabel}` : ''} whenever you open the app. You can change this in Settings → App lock.
        </p>
        <div className="lock-actions">
          <button type="button" className="btn btn-primary" onClick={() => setStep('create')} data-testid="pin-setup-start">
            Set up a PIN
          </button>
          {onSkip && (
            <PinLink onClick={onSkip} testId="pin-setup-skip">
              Not now
            </PinLink>
          )}
        </div>
      </div>
    )
  }

  if (step === 'biometric') {
    return (
      <div className="lock-screen" role="dialog" aria-modal="true" aria-label={biometricLabel} data-testid="pin-setup-biometric" data-sensitive-screen="lock">
        <h1 className="lock-title">Unlock with {biometricLabel}?</h1>
        <p className="lock-sub">Open OraSec with a glance or a touch. Your PIN still works, and you can change this in Settings.</p>
        <div className="lock-actions">
          <button
            type="button"
            className="btn btn-primary"
            disabled={busy}
            onClick={async () => {
              setBusy(true)
              const ok = await verifyBiometric()
              setBusy(false)
              if (ok) enableBiometric()
              onDone()
            }}
            data-testid="pin-setup-biometric-on"
          >
            {busy ? 'Waiting…' : 'Turn on'}
          </button>
          <PinLink onClick={onDone} testId="pin-setup-biometric-skip">
            Not now
          </PinLink>
        </div>
      </div>
    )
  }

  return (
    <PinPad
      key={step}
      testId="pin-setup"
      title={step === 'create' ? 'Create a 6-digit PIN' : 'Confirm your PIN'}
      subtitle={
        step === 'create'
          ? required
            ? 'Your app lock is on. Choose a new PIN to open OraSec on this device.'
            : 'You’ll use it to open OraSec on this device.'
          : 'Enter the same PIN again.'
      }
      error={error}
      busy={busy}
      onComplete={step === 'create' ? onFirst : onConfirm}
      footer={
        onSkip && !pinSaved ? (
          <PinLink onClick={onSkip} testId="pin-setup-cancel">
            {required ? 'Turn off app lock' : 'Not now'}
          </PinLink>
        ) : undefined
      }
    />
  )
}

