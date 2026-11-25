import { type ReactNode, useEffect, useId, useRef, useState } from 'react'

import { I, Icon } from '@/components/ui/ds'
import { useBackButtonClose } from '@/hooks/useBackButtonClose'

/**
 * Bottom sheet (phone) / centred dialog (tablet) for actions and forms.
 * Uses the shared `.sheet` styles; Escape and the Android back button close
 * it; focus moves into the sheet and returns to the opener on close.
 */
export function Sheet({
  open,
  title,
  onClose,
  children,
  footer,
  dismissible = true,
  wide = false,
}: {
  open: boolean
  title: string
  onClose: () => void
  children: ReactNode
  footer?: ReactNode
  dismissible?: boolean
  wide?: boolean
}) {
  const titleId = useId()
  const ref = useRef<HTMLDivElement>(null)
  const opener = useRef<Element | null>(null)
  const [shown, setShown] = useState(false)

  useBackButtonClose(open && dismissible, onClose)

  useEffect(() => {
    if (!open) {
      setShown(false)
      return
    }
    opener.current = document.activeElement
    const raf = requestAnimationFrame(() => {
      setShown(true)
      const el = ref.current
      const first = el?.querySelector<HTMLElement>('[data-autofocus]') ?? el
      first?.focus({ preventScroll: true })
    })
    return () => {
      cancelAnimationFrame(raf)
      const prev = opener.current
      if (prev instanceof HTMLElement && document.contains(prev)) prev.focus({ preventScroll: true })
    }
  }, [open])

  if (!open) return null

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape' && dismissible) {
      e.stopPropagation()
      onClose()
      return
    }
    if (e.key !== 'Tab' || !ref.current) return
    const focusables = ref.current.querySelectorAll<HTMLElement>(
      'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
    )
    if (focusables.length === 0) return
    const first = focusables[0]
    const last = focusables[focusables.length - 1]
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault()
      last.focus()
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault()
      first.focus()
    }
  }

  return (
    <>
      <div
        className={`sheet-scrim sg-scrim${shown ? ' open' : ''}`}
        onClick={dismissible ? onClose : undefined}
        aria-hidden="true"
      />
      <div
        ref={ref}
        className={`sheet sg-sheet${wide ? ' wide' : ''}${shown ? ' open' : ''}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        onKeyDown={onKeyDown}
      >
        <div className="grab" aria-hidden="true" />
        <div className="sheet-head">
          <h3 id={titleId}>{title}</h3>
          {dismissible ? (
            <button type="button" className="sg-icon-btn" aria-label="Close" onClick={onClose}>
              <Icon d={I.close} size={20} />
            </button>
          ) : null}
        </div>
        <div className="sheet-body">{children}</div>
        {footer ? <div className="sg-sheet-foot">{footer}</div> : null}
      </div>
    </>
  )
}

