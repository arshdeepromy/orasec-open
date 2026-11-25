import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, act } from '@testing-library/react'
import OraBubble from '../OraBubble'
import { BUBBLE_POS_KEY, LONG_PRESS_MS } from '../bubbleMath'

function mockReducedMotion(reduce: boolean) {
  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    writable: true,
    value: vi.fn().mockImplementation((q: string) => ({
      matches: reduce && q.includes('prefers-reduced-motion'),
      media: q,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      addListener: vi.fn(),
      removeListener: vi.fn(),
      onchange: null,
      dispatchEvent: vi.fn(),
    })),
  })
}

const TRACK = { left: 0, top: 0, width: 390, height: 600, right: 390, bottom: 600, x: 0, y: 0, toJSON: () => ({}) }

beforeEach(() => {
  localStorage.removeItem(BUBBLE_POS_KEY)
  mockReducedMotion(true)
  vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(function (this: HTMLElement) {
    return (this.dataset.testid === 'ora-bubble-track' ? TRACK : { ...TRACK, width: 56, height: 56 }) as DOMRect
  })
})

afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
})

const down = (el: Element, x: number, y: number) => fireEvent.pointerDown(el, { pointerId: 1, button: 0, clientX: x, clientY: y })
const move = (el: Element, x: number, y: number) => fireEvent.pointerMove(el, { pointerId: 1, clientX: x, clientY: y })
const up = (el: Element, x: number, y: number) => fireEvent.pointerUp(el, { pointerId: 1, clientX: x, clientY: y })

describe('OraBubble', () => {
  it('starts bottom-right and opens Ora on a tap', () => {
    const onOpen = vi.fn()
    const onLongPress = vi.fn()
    render(<OraBubble onOpen={onOpen} onLongPress={onLongPress} />)
    const b = screen.getByTestId('ora-bubble')
    expect(b).toHaveAttribute('data-side', 'right')
    expect(b.style.transform).toBe('translate3d(322px, 544px, 0)')
    down(b, 350, 570)
    up(b, 351, 571)
    expect(onOpen).toHaveBeenCalledTimes(1)
    expect(onLongPress).not.toHaveBeenCalled()
  })

  it('opens from the keyboard too', () => {
    const onOpen = vi.fn()
    render(<OraBubble onOpen={onOpen} onLongPress={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: 'Open Ora assistant' }), { detail: 0 })
    expect(onOpen).toHaveBeenCalledTimes(1)
  })

  it('long-press offers options instead of opening', () => {
    vi.useFakeTimers()
    const onOpen = vi.fn()
    const onLongPress = vi.fn()
    render(<OraBubble onOpen={onOpen} onLongPress={onLongPress} />)
    const b = screen.getByTestId('ora-bubble')
    down(b, 350, 570)
    act(() => {
      vi.advanceTimersByTime(LONG_PRESS_MS + 10)
    })
    up(b, 350, 570)
    expect(onLongPress).toHaveBeenCalledTimes(1)
    expect(onOpen).not.toHaveBeenCalled()
  })

  it('drags, snaps to the nearer edge and remembers the spot', () => {
    vi.useFakeTimers()
    const onOpen = vi.fn()
    const onLongPress = vi.fn()
    render(<OraBubble onOpen={onOpen} onLongPress={onLongPress} />)
    const b = screen.getByTestId('ora-bubble')
    down(b, 350, 570)
    move(b, 200, 400)
    move(b, 60, 300)
    up(b, 60, 300)
    act(() => {
      vi.advanceTimersByTime(LONG_PRESS_MS + 10)
    })
    expect(b).toHaveAttribute('data-side', 'left')
    expect(onOpen).not.toHaveBeenCalled()
    expect(onLongPress).not.toHaveBeenCalled()
    const saved = JSON.parse(localStorage.getItem(BUBBLE_POS_KEY) ?? '{}') as { side: string; y: number }
    expect(saved.side).toBe('left')
    expect(saved.y).toBeCloseTo((300 - 28) / (600 - 56), 2)
    // Settled against the left edge.
    expect(b.style.transform.startsWith('translate3d(12px,')).toBe(true)
  })

  it('restores a remembered position', () => {
    localStorage.setItem(BUBBLE_POS_KEY, JSON.stringify({ side: 'left', y: 0 }))
    render(<OraBubble onOpen={vi.fn()} onLongPress={vi.fn()} />)
    const b = screen.getByTestId('ora-bubble')
    expect(b).toHaveAttribute('data-side', 'left')
    expect(b.style.transform).toBe('translate3d(12px, 0px, 0)')
  })

  it('draws a static orb with prefers-reduced-motion (no animation frames)', () => {
    const raf = vi.spyOn(window, 'requestAnimationFrame')
    const { container } = render(<OraBubble onOpen={vi.fn()} onLongPress={vi.fn()} />)
    expect(container.ownerDocument.querySelector('[data-testid="ora-bubble"] svg')).toHaveAttribute('data-reduced-motion', 'true')
    expect(raf).not.toHaveBeenCalled()
  })

  it('shows the sleeping orb when Ora is resting', () => {
    render(<OraBubble sleeping onOpen={vi.fn()} onLongPress={vi.fn()} />)
    expect(document.querySelector('[data-testid="ora-bubble"] svg')).toHaveAttribute('data-mood', 'sleeping')
  })
})

