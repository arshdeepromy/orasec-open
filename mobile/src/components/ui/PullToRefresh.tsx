import { type ReactNode, useRef, useState } from 'react'

import { I, Icon } from '@/components/ui/ds'
import { useHaptics } from '@/hooks/useHaptics'

const THRESHOLD = 64
const MAX_PULL = 110

const scroller = () => document.getElementById('main-scroll')
const reducedMotion = () =>
  typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches

/**
 * Pull-to-refresh for a screen inside the shell's scroll column
 * (#main-scroll). Pull down from the top past the threshold and release;
 * a light haptic marks the trigger. Also reachable without the gesture: every
 * list screen keeps a Refresh button (accessibility).
 */
export function PullToRefresh({
  onRefresh,
  children,
  getScrollEl,
}: {
  onRefresh: () => unknown
  children: ReactNode
  /** The element that scrolls (default: the shell's #main-scroll). Panes of a split view pass their own. */
  getScrollEl?: () => HTMLElement | null
}) {
  const scrollTop = () => ((getScrollEl ?? scroller)()?.scrollTop ?? 0)
  const haptics = useHaptics()
  const [pull, setPull] = useState(0)
  const [refreshing, setRefreshing] = useState(false)
  const startY = useRef<number | null>(null)
  const armed = useRef(false)

  const onTouchStart = (e: React.TouchEvent) => {
    if (refreshing || scrollTop() > 0) return
    startY.current = e.touches[0].clientY
    armed.current = false
  }

  const onTouchMove = (e: React.TouchEvent) => {
    if (startY.current === null) return
    const dy = e.touches[0].clientY - startY.current
    if (dy <= 0 || scrollTop() > 0) {
      setPull(0)
      return
    }
    const distance = Math.min(dy * 0.5, MAX_PULL)
    setPull(distance)
    if (distance >= THRESHOLD && !armed.current) {
      armed.current = true
      void haptics.light()
    } else if (distance < THRESHOLD) {
      armed.current = false
    }
  }

  const onTouchEnd = async () => {
    if (startY.current === null) return
    startY.current = null
    if (pull < THRESHOLD) {
      setPull(0)
      return
    }
    setRefreshing(true)
    setPull(THRESHOLD * 0.7)
    const started = Date.now()
    try {
      await onRefresh()
    } finally {
      const wait = Math.max(0, 600 - (Date.now() - started))
      window.setTimeout(() => {
        setRefreshing(false)
        setPull(0)
      }, wait)
    }
  }

  const visible = pull > 4 || refreshing
  return (
    <div onTouchStart={onTouchStart} onTouchMove={onTouchMove} onTouchEnd={onTouchEnd} onTouchCancel={onTouchEnd} className="ptr">
      <div
        className="ptr-indicator"
        style={{ height: pull, opacity: visible ? 1 : 0, transition: startY.current === null && !reducedMotion() ? 'height .2s ease' : 'none' }}
        aria-hidden={!refreshing}
        role={refreshing ? 'status' : undefined}
        aria-label={refreshing ? 'Refreshing' : undefined}
      >
        <span
          className={`ptr-spinner${refreshing ? ' spin' : ''}`}
          style={{ transform: refreshing ? undefined : `rotate(${Math.min(pull / THRESHOLD, 1) * 270}deg)` }}
        >
          <Icon d={I.refresh} size={20} />
        </span>
      </div>
      <div className="stack">{children}</div>
    </div>
  )
}

