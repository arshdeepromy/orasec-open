import { useCallback, useState } from 'react'

import { useBackButtonClose } from '@/hooks/useBackButtonClose'
import { checkPin, MAX_PIN_ATTEMPTS, pinProblem, setPin } from '@/security/appPin'

import { PinLink, PinPad } from './PinPad'

type Step = 'current' | 'new' | 'confirm'

/**
 * Settings → App lock → Change PIN: current PIN, then the new one twice.
 * Wrong current PINs count toward the same five-attempt limit as the lock
 * screen; the fifth calls `onLockedOut` (the caller signs the person out).
 * Ported from the publisher's invoicing app.
 */
export function ChangePin({
  userId,
  onDone,
  onCancel,
  onLockedOut,
}: {
  userId: string
  onDone: () => void
  onCancel: () => void
  onLockedOut: () => void
}) {
  const [step, setStep] = useState<Step>('current')
  const [next, setNext] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  useBackButtonClose(true, onCancel)

  const onCurrent = useCallback(
    async (pin: string) => {
      setBusy(true)
      const result = await checkPin(userId, pin)
      setBusy(false)
      if (result.ok) {
        setError(null)
        setStep('new')
        return
      }
      if (result.remaining <= 0) {
        onLockedOut()
        return
      }
      setError(`Wrong PIN. ${result.remaining} of ${MAX_PIN_ATTEMPTS} attempts left.`)
    },
    [userId, onLockedOut],
  )

  const onNew = useCallback((pin: string) => {
    const problem = pinProblem(pin)
    if (problem) {
      setError(problem)
      return
    }
    setError(null)
    setNext(pin)
    setStep('confirm')
  }, [])

  const onConfirm = useCallback(
    async (pin: string) => {
      if (pin !== next) {
        setNext('')
        setStep('new')
        setError('Those PINs didn’t match. Choose your new PIN again.')
        return
      }
      setBusy(true)
      try {
        await setPin(userId, pin)
        onDone()
      } catch (err) {
        setStep('new')
        setError(err instanceof Error ? err.message : 'Couldn’t save your PIN.')
      } finally {
        setBusy(false)
      }
    },
    [next, userId, onDone],
  )

  const titles: Record<Step, string> = {
    current: 'Enter your current PIN',
    new: 'Choose a new 6-digit PIN',
    confirm: 'Confirm your new PIN',
  }

  return (
    <PinPad
      key={step}
      testId="change-pin"
      title={titles[step]}
      error={error}
      busy={busy}
      onComplete={step === 'current' ? onCurrent : step === 'new' ? onNew : onConfirm}
      footer={<PinLink onClick={onCancel}>Cancel</PinLink>}
    />
  )
}

/**
 * Ask for the current PIN before a protected change (turning the app lock
 * off). Same five-attempt limit as the lock screen.
 */
export function ConfirmPin({
  userId,
  title = 'Enter your PIN',
  subtitle,
  onConfirmed,
  onCancel,
  onLockedOut,
}: {
  userId: string
  title?: string
  subtitle?: string
  onConfirmed: () => void
  onCancel: () => void
  onLockedOut: () => void
}) {
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  useBackButtonClose(true, onCancel)

  const onComplete = useCallback(
    async (pin: string) => {
      setBusy(true)
      const result = await checkPin(userId, pin)
      setBusy(false)
      if (result.ok) {
        onConfirmed()
        return
      }
      if (result.remaining <= 0) {
        onLockedOut()
        return
      }
      setError(`Wrong PIN. ${result.remaining} of ${MAX_PIN_ATTEMPTS} attempts left.`)
    },
    [userId, onConfirmed, onLockedOut],
  )

  return (
    <PinPad
      testId="confirm-pin"
      title={title}
      subtitle={subtitle}
      error={error}
      busy={busy}
      onComplete={onComplete}
      footer={<PinLink onClick={onCancel}>Cancel</PinLink>}
    />
  )
}

