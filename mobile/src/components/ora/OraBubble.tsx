/**
 * OraBubble — the floating Ora ball (requirements R1.4).
 *
 *   • ~56 px orb, draggable with a finger (pointer events), snaps to the
 *     nearer left/right edge on release and remembers where it was left;
 *   • lives in a track that keeps it clear of the status bar / navbar and of
 *     the tab bar + screen FABs (safe areas included), so it never covers them;
 *   • tap → open the Ora sheet; long-press → `onLongPress` (the host offers
 *     "Hide Ora"); keyboard Enter/Space opens too;
 *   • hidden while the on-screen keyboard is up.
 */
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'
import type { PointerEvent as ReactPointerEvent } from 'react'
import OraOrb from './OraOrb'
import {
  BUBBLE_SIZE,
  LONG_PRESS_MS,
  bubbleOffset,
  dragOffset,
  isDrag,
  readBubblePos,
  snapToEdge,
  writeBubblePos,
} from './bubbleMath'
import type { BubblePos } from './bubbleMath'
import { OraPortal, Z_BUBBLE } from './oraUi'

interface Props {
  sleeping?: boolean
  onOpen: () => void
  onLongPress: () => void
}

/** Room kept clear at the top (navbar) and bottom (tab bar + FAB) of the screen. */
const TRACK_TOP = 'calc(var(--safe-top, 0px) + 60px)'
const TRACK_BOTTOM = 'calc(var(--safe-bot, 0px) + 150px)'

export default function OraBubble({ sleeping = false, onOpen, onLongPress }: Props) {
  const trackRef = useRef<HTMLDivElement>(null)
  const [track, setTrack] = useState<{ w: number; h: number }>({ w: 0, h: 0 })
  const [pos, setPos] = useState<BubblePos>(() => readBubblePos())
  const [drag, setDrag] = useState<{ x: number; y: number } | null>(null)
  const gesture = useRef<{
    id: number
    startX: number
    startY: number
    dragging: boolean
    longPressed: boolean
    timer: number | undefined
  } | null>(null)

  const measure = useCallback(() => {
    const r = trackRef.current?.getBoundingClientRect()
    if (r) setTrack({ w: r.width, h: r.height })
  }, [])

  useLayoutEffect(() => {
    measure()
  }, [measure])

  useEffect(() => {
    window.addEventListener('resize', measure)
    window.addEventListener('orientationchange', measure)
    return () => {
      window.removeEventListener('resize', measure)
      window.removeEventListener('orientationchange', measure)
      if (gesture.current?.timer) window.clearTimeout(gesture.current.timer)
    }
  }, [measure])

  const local = (e: ReactPointerEvent) => {
    const r = trackRef.current?.getBoundingClientRect()
    return { x: e.clientX - (r?.left ?? 0), y: e.clientY - (r?.top ?? 0) }
  }

  const onPointerDown = (e: ReactPointerEvent<HTMLButtonElement>) => {
    if (e.button !== undefined && e.button !== 0) return
    try {
      e.currentTarget.setPointerCapture?.(e.pointerId)
    } catch {
      /* synthetic events in tests */
    }
    const timer = window.setTimeout(() => {
      const g = gesture.current
      if (g && !g.dragging) {
        g.longPressed = true
        onLongPress()
      }
    }, LONG_PRESS_MS)
    gesture.current = { id: e.pointerId, startX: e.clientX, startY: e.clientY, dragging: false, longPressed: false, timer }
  }

  const onPointerMove = (e: ReactPointerEvent<HTMLButtonElement>) => {
    const g = gesture.current
    if (!g || g.id !== e.pointerId || g.longPressed) return
    if (!g.dragging && !isDrag(e.clientX - g.startX, e.clientY - g.startY)) return
    if (!g.dragging) {
      g.dragging = true
      window.clearTimeout(g.timer)
    }
    const p = local(e)
    setDrag(dragOffset(p.x, p.y, track.w, track.h))
  }

  const finish = (e: ReactPointerEvent<HTMLButtonElement>, cancelled: boolean) => {
    const g = gesture.current
    gesture.current = null
    if (!g) return
    window.clearTimeout(g.timer)
    if (g.dragging) {
      const p = local(e)
      const next = snapToEdge(p.x, p.y, track.w, track.h)
      setPos(next)
      writeBubblePos(next)
      setDrag(null)
      return
    }
    if (!cancelled && !g.longPressed) onOpen()
  }

  const at = drag ?? bubbleOffset(pos, track.w, track.h)

  return (
    <OraPortal>
      {/* Hidden while the keyboard is up (native/capacitor-init sets body.keyboard-open). */}
      <style>{'body.keyboard-open .ora-bubble-track{display:none}'}</style>
      <div
        ref={trackRef}
        className="ora-bubble-track pointer-events-none fixed"
        style={{
          zIndex: Z_BUBBLE,
          top: TRACK_TOP,
          bottom: TRACK_BOTTOM,
          left: 'max(env(safe-area-inset-left, 0px), var(--android-inset-left, 0px))',
          right: 'max(env(safe-area-inset-right, 0px), var(--android-inset-right, 0px))',
        }}
        data-testid="ora-bubble-track"
      >
        <button
          type="button"
          aria-label="Open Ora assistant"
          title="Ora — long-press for options"
          data-testid="ora-bubble"
          data-side={pos.side}
          className="pointer-events-auto absolute left-0 top-0 grid place-items-center rounded-full"
          style={{
            width: BUBBLE_SIZE,
            height: BUBBLE_SIZE,
            transform: `translate3d(${Math.round(at.x)}px, ${Math.round(at.y)}px, 0)`,
            transition: drag ? 'none' : 'transform 0.22s cubic-bezier(0.2, 0.8, 0.2, 1)',
            touchAction: 'none',
            WebkitTouchCallout: 'none',
            userSelect: 'none',
            filter: 'drop-shadow(0 6px 14px rgba(0, 60, 50, 0.35))',
            visibility: track.h > 0 ? 'visible' : 'hidden',
          }}
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={(e) => finish(e, false)}
          onPointerCancel={(e) => finish(e, true)}
          onContextMenu={(e) => e.preventDefault()}
          onClick={(e) => {
            // Pointer taps are handled on pointer-up; this is keyboard / screen-reader activation.
            if (e.detail === 0) onOpen()
          }}
        >
          <OraOrb mood={sleeping ? 'sleeping' : 'idle'} size={BUBBLE_SIZE} decorative />
        </button>
      </div>
    </OraPortal>
  )
}

