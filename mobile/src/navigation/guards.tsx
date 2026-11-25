import type { ReactNode } from 'react'
import { Navigate, useLocation } from 'react-router-dom'

import { Screen, StateBlock } from '@/components/ui/ds'
import { useAuth } from '@/contexts/AuthContext'
import { peekReturnTo, rememberReturnTo } from '@/navigation/returnTo'

export function Splash() {
  return (
    <div className="flex min-h-[60vh] items-center justify-center" aria-busy="true" aria-label="Loading">
      <span className="sk sk-av" />
    </div>
  )
}

/** Linked phones only; remembers where the user was going. */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { status } = useAuth()
  const location = useLocation()
  if (status === 'loading') return <Splash />
  if (status !== 'signedIn') {
    rememberReturnTo(`${location.pathname}${location.search}`)
    return <Navigate to="/link" replace state={{ from: location.pathname }} />
  }
  return <>{children}</>
}

/** Signed-out only (sign-in flows). */
export function GuestOnly({ children }: { children: ReactNode }) {
  const { status } = useAuth()
  const location = useLocation()
  const from = (location.state as { from?: unknown } | null)?.from
  if (from) rememberReturnTo(from)
  if (status === 'loading') return <Splash />
  if (status === 'signedIn') return <Navigate to={peekReturnTo()} replace />
  return <>{children}</>
}

export function NotFound() {
  return (
    <Screen title="Not found" back>
      <StateBlock kind="error" title="This screen isn't available" body="Go back and try again." />
    </Screen>
  )
}

/** Temporary body for a screen that is still being built. */
export function ComingSoon({ title, back = true }: { title: string; back?: boolean | string }) {
  return (
    <Screen title={title} back={back}>
      <StateBlock title="Coming soon" body="This screen is being built." />
    </Screen>
  )
}

