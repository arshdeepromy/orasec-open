import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import OraOrb, {
  ORB_SHAPES,
  WORK_CYCLE,
  MORPH_MS,
  easeInOutCubic,
  shapeToPath,
  workingShapeAt,
} from '../OraOrb'

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

afterEach(() => {
  vi.restoreAllMocks()
})

describe('OraOrb shapes', () => {
  it('every shape has 26 numbers and starts/ends on the same point', () => {
    for (const nums of Object.values(ORB_SHAPES)) {
      expect(nums).toHaveLength(26)
      expect(nums[0]).toBe(nums[24])
      expect(nums[1]).toBe(nums[25])
    }
  })

  it('builds M + four C segments', () => {
    const d = shapeToPath(ORB_SHAPES.circle)
    expect(d.startsWith('M60 22')).toBe(true)
    expect(d.match(/C/g)).toHaveLength(4)
  })

  it('easeInOutCubic is clamped and symmetric', () => {
    expect(easeInOutCubic(0)).toBe(0)
    expect(easeInOutCubic(1)).toBe(1)
    expect(easeInOutCubic(0.5)).toBeCloseTo(0.5)
    expect(easeInOutCubic(-1)).toBe(0)
    expect(easeInOutCubic(2)).toBe(1)
  })

  it('working cycle lands exactly on each shape at step boundaries', () => {
    expect(WORK_CYCLE).toEqual(['squircle', 'star', 'blob', 'tri', 'pill', 'circle'])
    // At the start of step k the morph is at its "from" shape (= previous step's target).
    expect(workingShapeAt(MORPH_MS * 1)).toEqual([...ORB_SHAPES.squircle])
    expect(workingShapeAt(MORPH_MS * 2)).toEqual([...ORB_SHAPES.star])
    expect(workingShapeAt(MORPH_MS * 6)).toEqual([...ORB_SHAPES.circle])
  })
})

describe('OraOrb component', () => {
  it('renders a static frame and never schedules rAF with prefers-reduced-motion', () => {
    mockReducedMotion(true)
    const raf = vi.spyOn(window, 'requestAnimationFrame')
    render(<OraOrb mood="idle" />)
    const svg = screen.getByRole('img', { name: 'Ora' })
    expect(svg).toHaveAttribute('data-reduced-motion', 'true')
    expect(raf).not.toHaveBeenCalled()
    expect(screen.getByTestId('ora-orb-body')).toHaveAttribute('d', shapeToPath(ORB_SHAPES.circle))
  })

  it('animates with rAF and cancels it on unmount', () => {
    mockReducedMotion(false)
    const raf = vi.spyOn(window, 'requestAnimationFrame').mockImplementation(() => 42)
    const cancel = vi.spyOn(window, 'cancelAnimationFrame').mockImplementation(() => undefined)
    const { unmount } = render(<OraOrb mood="working" />)
    expect(raf).toHaveBeenCalled()
    unmount()
    expect(cancel).toHaveBeenCalledWith(42)
  })

  it('working mood uses the short dashed ring', () => {
    mockReducedMotion(true)
    render(<OraOrb mood="working" />)
    expect(screen.getByTestId('ora-orb-ring')).toHaveAttribute('stroke-dasharray', '16 10')
  })

  it('happy shows smile arcs, sleeping shows closed eyes', () => {
    mockReducedMotion(true)
    const { rerender, container } = render(<OraOrb mood="happy" />)
    expect(container.querySelectorAll('[data-testid="ora-orb-eyes"] ellipse')).toHaveLength(0)
    expect(container.querySelector('path[d="M45 64 Q50 55 55 64"]')).not.toBeNull()
    rerender(<OraOrb mood="sleeping" />)
    expect(container.querySelectorAll('[data-testid="ora-orb-eyes"] ellipse')).toHaveLength(0)
    rerender(<OraOrb mood="sorry" />)
    const eyes = container.querySelectorAll('[data-testid="ora-orb-eyes"] ellipse')
    expect(eyes).toHaveLength(2)
    expect(eyes[0]).toHaveAttribute('ry', '5')
  })

  it('gives every instance its own clipPath id', () => {
    mockReducedMotion(true)
    const { container } = render(
      <>
        <OraOrb />
        <OraOrb />
      </>,
    )
    const ids = Array.from(container.querySelectorAll('clipPath')).map((c) => c.id)
    expect(ids).toHaveLength(2)
    expect(new Set(ids).size).toBe(2)
  })

  it('can be decorative', () => {
    mockReducedMotion(true)
    const { container } = render(<OraOrb decorative />)
    expect(container.querySelector('svg')).toHaveAttribute('aria-hidden', 'true')
    expect(screen.queryByRole('img')).toBeNull()
  })
})

