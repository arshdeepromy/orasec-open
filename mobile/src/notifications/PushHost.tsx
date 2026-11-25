import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'

import { useAuth } from '@/contexts/AuthContext'
import { isDemoSession } from '@/demo/session'
import { clearDeliveredPush, onPushTap } from '@/native/push'
import { refreshPushRegistration, safeTapPath } from '@/notifications/pushController'

/**
 * Keeps notifications working while the app runs: refreshes the phone's address after sign-in and opens the right
 * screen when a notification is tapped. Renders nothing.
 */
export default function PushHost() {
  const { status } = useAuth()
  const navigate = useNavigate()

  useEffect(() => {
    if (status !== 'signedIn' || isDemoSession()) return
    void refreshPushRegistration()
    void clearDeliveredPush()
  }, [status])

  useEffect(() => {
    let stop: (() => void) | null = null
    let cancelled = false
    void onPushTap((tap) => {
      const path = safeTapPath(tap.path)
      if (path) navigate(path)
      void clearDeliveredPush()
    }).then((remove) => {
      if (cancelled) remove()
      else stop = remove
    })
    return () => {
      cancelled = true
      stop?.()
    }
  }, [navigate])

  return null
}
