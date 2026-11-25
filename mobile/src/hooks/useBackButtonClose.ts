import { useEffect, useRef } from 'react'
import { pushBackHandler } from '@/native/backButton'

/**
 * While `active`, the Android back button calls `onBack` (close this sheet,
 * go to the previous wizard step, …) instead of leaving the screen.
 * Overlays opened later sit on top, so back always closes the top-most one.
 */
export function useBackButtonClose(active: boolean, onBack: (() => void) | undefined): void {
  const ref = useRef(onBack)
  useEffect(() => {
    ref.current = onBack
  })
  useEffect(() => {
    if (!active) return
    return pushBackHandler(() => ref.current?.())
  }, [active])
}
