import { useEffect, useState } from 'react'

/**
 * Phone vs tablet layout.
 *
 * - phone  (< 600 CSS px): bottom tab bar, one column.
 * - tablet (600–1179): a compact navigation rail on the left, multi-column screens. Covers 7" Android tablets in
 *   portrait (600dp), 10" tablets (800dp portrait / 1280dp landscape) and iPads in portrait.
 * - wide   (≥ 1180): the full sidebar with labels and sections (iPad landscape, 10"+ landscape).
 *
 * `split` (≥ 900): list + detail side by side (Vulnerabilities).
 */
export const TABLET_MIN_WIDTH = 600
export const SPLIT_MIN_WIDTH = 900
export const WIDE_MIN_WIDTH = 1180

export type LayoutSize = 'phone' | 'tablet' | 'wide'

export const sizeFor = (width: number): LayoutSize =>
  width >= WIDE_MIN_WIDTH ? 'wide' : width >= TABLET_MIN_WIDTH ? 'tablet' : 'phone'

export function useLayout(): { size: LayoutSize; isTablet: boolean; split: boolean; width: number } {
  const [width, setWidth] = useState(() => (typeof window === 'undefined' ? 390 : window.innerWidth))

  useEffect(() => {
    const onResize = () => setWidth(window.innerWidth)
    window.addEventListener('resize', onResize)
    window.addEventListener('orientationchange', onResize)
    return () => {
      window.removeEventListener('resize', onResize)
      window.removeEventListener('orientationchange', onResize)
    }
  }, [])

  const size = sizeFor(width)
  return { size, isTablet: size !== 'phone', split: width >= SPLIT_MIN_WIDTH, width }
}

