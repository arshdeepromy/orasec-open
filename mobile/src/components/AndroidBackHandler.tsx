import { useEffect, useRef } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { setBackFallback } from '@/native/backButton'

/** Screens where back leaves the app (minimise) rather than navigating. */
const ROOT_PATHS = new Set(['/', '/vulns', '/attacks', '/governance', '/more', '/link'])

function minimise() {
  import('@capacitor/app')
    .then(({ App }) => App.minimizeApp())
    .catch(() => {})
}

/**
 * Router-level Android back behaviour, used when no sheet/drawer/step is open:
 * root screens minimise, anything with history pops it, and a screen reached
 * with no history (deep link, push notification, restored state) goes Home
 * instead of closing the app.
 */
export function AndroidBackHandler() {
  const navigate = useNavigate()
  const location = useLocation()
  const pathRef = useRef(location.pathname)
  useEffect(() => {
    pathRef.current = location.pathname
  }, [location.pathname])

  useEffect(
    () =>
      setBackFallback(() => {
        const path = pathRef.current.replace(/^\/mobile/, '').replace(/\/$/, '') || '/'
        if (ROOT_PATHS.has(path)) {
          minimise()
          return
        }
        const idx = (window.history.state as { idx?: number } | null)?.idx ?? 0
        if (idx > 0) navigate(-1)
        else navigate('/', { replace: true })
      }),
    [navigate],
  )
  return null
}
