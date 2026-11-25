import { useCallback, useEffect, useState, type ReactNode } from 'react'

import { PIN_LENGTH } from '@/security/appPin'

import './security.css'

interface PinPadProps {
  title: string
  subtitle?: ReactNode
  /** Shown under the dots (wrong PIN, PIN too simple, …). Announced. */
  error?: string | null
  /** Called with the full PIN once all digits are in. The pad clears after. */
  onComplete: (pin: string) => void | Promise<void>
  busy?: boolean
  /** Optional Face ID / fingerprint key in the bottom-left of the keypad. */
  biometric?: { label: string; onPress: () => void }
  /** Links under the keypad (Forgot PIN?, Sign out, …). */
  footer?: ReactNode
  testId?: string
}

const KEYS = ['1', '2', '3', '4', '5', '6', '7', '8', '9']

/**
 * Full-screen numeric PIN entry — six dots and a phone-style keypad. Used by
 * the app lock, first-time PIN setup and Settings → App lock → Change PIN.
 * Ported from the publisher's invoicing app, restyled with the
 * design-system variables. Marked `data-sensitive-screen`, so screenshots and
 * the app-switcher snapshot are blocked while it is up (native/privacyScreen).
 */
export function PinPad({
  title,
  subtitle,
  error,
  onComplete,
  busy = false,
  biometric,
  footer,
  testId = 'pin-pad',
}: PinPadProps) {
  const [digits, setDigits] = useState('')
  const [submitting, setSubmitting] = useState(false)

  // A new error (wrong PIN) empties the dots for the next try.
  useEffect(() => {
    if (error) setDigits('')
  }, [error])

  // All digits in: hand over (after the last dot has painted), then clear.
  useEffect(() => {
    if (digits.length !== PIN_LENGTH || submitting) return
    setSubmitting(true)
    const pin = digits
    const timer = setTimeout(() => {
      void Promise.resolve()
        .then(() => onComplete(pin))
        .finally(() => {
          setDigits('')
          setSubmitting(false)
        })
    }, 80)
    return () => clearTimeout(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [digits])

  const press = useCallback(
    (d: string) => {
      if (busy || submitting) return
      setDigits((cur) => (cur.length >= PIN_LENGTH ? cur : cur + d))
    },
    [busy, submitting],
  )

  const back = useCallback(() => {
    if (!busy) setDigits((cur) => cur.slice(0, -1))
  }, [busy])

  // A hardware keyboard (iPad / Mac / tablet with a keyboard): digit keys type
  // the PIN, Backspace deletes. Ignored while another field has focus.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey) return
      const el = document.activeElement as HTMLElement | null
      if (el && (el.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName))) return
      if (/^[0-9]$/.test(e.key)) {
        e.preventDefault()
        press(e.key)
      } else if (e.key === 'Backspace' || e.key === 'Delete') {
        e.preventDefault()
        back()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [press, back])

  return (
    <div className="lock-screen" role="dialog" aria-modal="true" aria-label={title} data-testid={testId} data-sensitive-screen="pin">
      <h1 className="lock-title">{title}</h1>
      <p className="lock-sub">{subtitle ?? ''}</p>

      <div className="pin-dots" role="img" aria-label={`${digits.length} of ${PIN_LENGTH} digits entered`}>
        {Array.from({ length: PIN_LENGTH }, (_, i) => (
          <span key={i} className={`pin-dot${i < digits.length ? ' on' : ''}`} />
        ))}
      </div>

      <p role="alert" className="pin-error">
        {error ?? ''}
      </p>

      <div className="pin-grid">
        {KEYS.map((k) => (
          <button key={k} type="button" className="pin-key" onClick={() => press(k)} disabled={busy} aria-label={k}>
            {k}
          </button>
        ))}
        {biometric ? (
          <button
            type="button"
            onClick={biometric.onPress}
            disabled={busy}
            aria-label={biometric.label}
            data-testid="pin-biometric"
            className="pin-key plain accent"
          >
            <FaceIcon />
          </button>
        ) : (
          <span />
        )}
        <button type="button" className="pin-key" onClick={() => press('0')} disabled={busy} aria-label="0">
          0
        </button>
        <button type="button" onClick={back} disabled={busy || digits.length === 0} aria-label="Delete" className="pin-key plain">
          <BackspaceIcon />
        </button>
      </div>

      {footer && <div className="pin-footer">{footer}</div>}
    </div>
  )
}

function FaceIcon() {
  return (
    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M4 8V6a2 2 0 0 1 2-2h2M16 4h2a2 2 0 0 1 2 2v2M20 16v2a2 2 0 0 1-2 2h-2M8 20H6a2 2 0 0 1-2-2v-2" />
      <path d="M9 9.5v1M15 9.5v1M12 9.5v3.5h-1M9.5 15.5a3.5 3.5 0 0 0 5 0" />
    </svg>
  )
}

function BackspaceIcon() {
  return (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M21 5H9l-6 7 6 7h12a1 1 0 0 0 1-1V6a1 1 0 0 0-1-1Z" />
      <path d="m16 9-5 6M11 9l5 6" />
    </svg>
  )
}

/** Small text button for the pad footer. */
export function PinLink({ children, onClick, testId }: { children: ReactNode; onClick: () => void; testId?: string }) {
  return (
    <button type="button" onClick={onClick} data-testid={testId} className="pin-link">
      {children}
    </button>
  )
}

