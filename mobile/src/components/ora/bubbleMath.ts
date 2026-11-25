/**
 * Pure maths for the draggable Ora bubble (requirements R1.4).
 *
 * The bubble lives in a fixed "track" box that already excludes the status
 * bar / navbar at the top and the tab bar + FAB area at the bottom (CSS with
 * the safe-area variables, measured at runtime), so these functions only deal
 * with plain track coordinates:
 *
 *   • position = which edge (left | right) + a 0..1 fraction of the track's
 *     free height, so it survives rotation and different screen sizes;
 *   • on release the bubble snaps to the nearer edge;
 *   • a move under DRAG_THRESHOLD px is a tap, not a drag.
 */

export type BubbleSide = 'left' | 'right'

export interface BubblePos {
  side: BubbleSide
  /** 0 = top of the track, 1 = bottom. */
  y: number
}

export const BUBBLE_SIZE = 56
export const EDGE_MARGIN = 12
export const DRAG_THRESHOLD = 6
export const LONG_PRESS_MS = 550
export const BUBBLE_POS_KEY = 'ora.bubble.pos.v1'

/** Bottom-right, just above the tab bar and any screen FAB. */
export const DEFAULT_BUBBLE_POS: BubblePos = { side: 'right', y: 1 }

export function clamp01(v: number): number {
  if (!Number.isFinite(v)) return 1
  return Math.min(1, Math.max(0, v))
}

/** Where the bubble settles when released with its centre at (cx, cy). */
export function snapToEdge(cx: number, cy: number, trackW: number, trackH: number, size = BUBBLE_SIZE): BubblePos {
  const side: BubbleSide = cx < trackW / 2 ? 'left' : 'right'
  const free = Math.max(0, trackH - size)
  const y = free === 0 ? 0 : clamp01((cy - size / 2) / free)
  return { side, y }
}

/** Top-left of the bubble inside the track for a stored position. */
export function bubbleOffset(
  pos: BubblePos,
  trackW: number,
  trackH: number,
  size = BUBBLE_SIZE,
  margin = EDGE_MARGIN,
): { x: number; y: number } {
  const x = pos.side === 'left' ? margin : Math.max(margin, trackW - size - margin)
  const y = clamp01(pos.y) * Math.max(0, trackH - size)
  return { x, y }
}

/** Top-left while dragging: follow the finger but stay inside the track. */
export function dragOffset(
  cx: number,
  cy: number,
  trackW: number,
  trackH: number,
  size = BUBBLE_SIZE,
): { x: number; y: number } {
  const x = Math.min(Math.max(0, cx - size / 2), Math.max(0, trackW - size))
  const y = Math.min(Math.max(0, cy - size / 2), Math.max(0, trackH - size))
  return { x, y }
}

export function isDrag(dx: number, dy: number, threshold = DRAG_THRESHOLD): boolean {
  return Math.hypot(dx, dy) >= threshold
}

/** A stored position, or the default when missing / malformed. */
export function parseBubblePos(raw: string | null | undefined): BubblePos {
  if (!raw) return DEFAULT_BUBBLE_POS
  try {
    const v = JSON.parse(raw) as { side?: unknown; y?: unknown }
    if ((v?.side === 'left' || v?.side === 'right') && typeof v.y === 'number' && Number.isFinite(v.y)) {
      return { side: v.side, y: clamp01(v.y) }
    }
  } catch {
    /* fall through */
  }
  return DEFAULT_BUBBLE_POS
}

export function readBubblePos(): BubblePos {
  try {
    return parseBubblePos(localStorage.getItem(BUBBLE_POS_KEY))
  } catch {
    return DEFAULT_BUBBLE_POS
  }
}

export function writeBubblePos(pos: BubblePos) {
  try {
    localStorage.setItem(BUBBLE_POS_KEY, JSON.stringify({ side: pos.side, y: Math.round(clamp01(pos.y) * 1000) / 1000 }))
  } catch {
    /* private mode / storage full: the bubble just starts at the default */
  }
}

