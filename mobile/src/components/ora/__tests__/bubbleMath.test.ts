import { describe, it, expect, beforeEach } from 'vitest'
import {
  BUBBLE_POS_KEY,
  BUBBLE_SIZE,
  DEFAULT_BUBBLE_POS,
  EDGE_MARGIN,
  bubbleOffset,
  clamp01,
  dragOffset,
  isDrag,
  parseBubblePos,
  readBubblePos,
  snapToEdge,
  writeBubblePos,
} from '../bubbleMath'

const W = 390
const H = 600

describe('bubble edge snapping', () => {
  it('snaps to the nearer edge', () => {
    expect(snapToEdge(50, 300, W, H).side).toBe('left')
    expect(snapToEdge(W - 50, 300, W, H).side).toBe('right')
    // Exactly at the middle goes right (not left of centre).
    expect(snapToEdge(W / 2, 300, W, H).side).toBe('right')
    expect(snapToEdge(W / 2 - 1, 300, W, H).side).toBe('left')
  })

  it('stores y as a fraction of the free height, clamped to the track', () => {
    expect(snapToEdge(10, BUBBLE_SIZE / 2, W, H).y).toBe(0)
    expect(snapToEdge(10, H - BUBBLE_SIZE / 2, W, H).y).toBe(1)
    expect(snapToEdge(10, H / 2, W, H).y).toBeCloseTo(0.5, 5)
    // Dragged past the top / bottom (over the navbar or tab bar) → clamped.
    expect(snapToEdge(10, -200, W, H).y).toBe(0)
    expect(snapToEdge(10, H + 400, W, H).y).toBe(1)
  })

  it('places a stored position against the chosen edge inside the track', () => {
    expect(bubbleOffset({ side: 'left', y: 0 }, W, H)).toEqual({ x: EDGE_MARGIN, y: 0 })
    expect(bubbleOffset({ side: 'right', y: 1 }, W, H)).toEqual({ x: W - BUBBLE_SIZE - EDGE_MARGIN, y: H - BUBBLE_SIZE })
    // A position survives a different (rotated) track size.
    const pos = snapToEdge(W - 20, H / 2, W, H)
    expect(bubbleOffset(pos, 800, 300).y).toBeCloseTo((300 - BUBBLE_SIZE) / 2, 5)
  })

  it('never goes negative on a tiny track', () => {
    expect(bubbleOffset({ side: 'right', y: 1 }, 20, 20)).toEqual({ x: EDGE_MARGIN, y: 0 })
    expect(snapToEdge(5, 5, 20, 20).y).toBe(0)
  })

  it('follows the finger while dragging but stays inside the track', () => {
    expect(dragOffset(100, 100, W, H)).toEqual({ x: 100 - BUBBLE_SIZE / 2, y: 100 - BUBBLE_SIZE / 2 })
    expect(dragOffset(-50, -50, W, H)).toEqual({ x: 0, y: 0 })
    expect(dragOffset(W + 50, H + 50, W, H)).toEqual({ x: W - BUBBLE_SIZE, y: H - BUBBLE_SIZE })
  })

  it('treats a small wobble as a tap', () => {
    expect(isDrag(2, 3)).toBe(false)
    expect(isDrag(6, 0)).toBe(true)
    expect(isDrag(4, 5)).toBe(true)
  })

  it('clamps bad numbers', () => {
    expect(clamp01(Number.NaN)).toBe(1)
    expect(clamp01(-1)).toBe(0)
    expect(clamp01(3)).toBe(1)
  })
})

describe('remembered position', () => {
  beforeEach(() => localStorage.removeItem(BUBBLE_POS_KEY))

  it('defaults to bottom-right above the tab bar', () => {
    expect(DEFAULT_BUBBLE_POS).toEqual({ side: 'right', y: 1 })
    expect(readBubblePos()).toEqual(DEFAULT_BUBBLE_POS)
  })

  it('round-trips through storage', () => {
    writeBubblePos({ side: 'left', y: 0.33333 })
    expect(readBubblePos()).toEqual({ side: 'left', y: 0.333 })
  })

  it('ignores malformed values', () => {
    expect(parseBubblePos('not json')).toEqual(DEFAULT_BUBBLE_POS)
    expect(parseBubblePos('{"side":"top","y":0.5}')).toEqual(DEFAULT_BUBBLE_POS)
    expect(parseBubblePos('{"side":"left","y":"x"}')).toEqual(DEFAULT_BUBBLE_POS)
    expect(parseBubblePos('{"side":"left","y":7}')).toEqual({ side: 'left', y: 1 })
  })
})

