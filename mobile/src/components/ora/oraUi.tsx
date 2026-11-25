import type { ReactNode } from 'react'
import { createPortal } from 'react-dom'

export const Z_BUBBLE = 30
export const Z_SHEET = 80

function portalHost(): Element | null {
  if (typeof document === 'undefined') return null
  return document.querySelector('.k-app') ?? document.body
}

/** Render into the app root so no transformed ancestor traps `position: fixed`. */
export function OraPortal({ children }: { children: ReactNode }) {
  const host = portalHost()
  return host ? createPortal(children, host) : <>{children}</>
}

/** Stroke icons used in the Ora sheet (24px grid). */
export const ORA_ICONS = {
  close: 'M18 6L6 18M6 6l12 12',
  back: 'M15 18l-6-6 6-6',
  plus: 'M12 5v14M5 12h14',
  clock: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z',
  send: 'M6 12L3.27 3.13A59.8 59.8 0 0121.49 12 59.8 59.8 0 013.27 20.88L6 12zm0 0h7.5',
  go: 'M5 12h14M13 6l6 6-6 6',
  shield: 'M12 3L4 6v6c0 5 3.5 8.5 8 9 4.5-.5 8-4 8-9V6zM9 12l2 2 4-4',
  warn: 'M12 9v3.75m-9.3 3.38c-.87 1.5.22 3.37 1.95 3.37h14.7c1.73 0 2.82-1.87 1.95-3.37L13.95 3.38c-.87-1.5-3.03-1.5-3.9 0zM12 15.75h.01',
  trash: 'M19 7l-.87 12.14A2 2 0 0116.14 21H7.86a2 2 0 01-2-1.86L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16',
  note: 'M4 5h16v11H8l-4 4zM8 9h8M8 12h5',
  up: 'M7 10v11H4V10zm0 0l4-7.5c1.4 0 2.5 1.1 2.5 2.5v3h5.3a2 2 0 012 2.3l-1.4 8.2a2 2 0 01-2 1.7H7',
  down: 'M17 14V3h3v11zm0 0l-4 7.5c-1.4 0-2.5-1.1-2.5-2.5v-3H5.2a2 2 0 01-2-2.3l1.4-8.2a2 2 0 012-1.7H17',
}

export function OraIcon({ d, size = 20 }: { d: string; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={d} />
    </svg>
  )
}

