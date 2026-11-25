import markUrl from '@/assets/orasec-mark-256.png'

/**
 * OraSec brand mark used on the link, lock and no-access screens: the app icon
 * (teal shield and magnifier on the dark console tile). It brings its own dark
 * background, so it looks the same on every appearance.
 *
 * `src/assets/orasec-mark-256.png` (rounded, transparent corners) is made by
 * scripts/make-orasec-icon.mjs together with the store icons. Rerun it when the icon changes.
 */
export function BrandMark({ size = 80, className = '' }: { size?: number; className?: string }) {
  return (
    <img
      src={markUrl}
      width={size}
      height={size}
      alt="OraSec"
      draggable={false}
      className={className}
      style={{ width: size, height: size, borderRadius: Math.round(size * 0.225), objectFit: 'cover' }}
    />
  )
}

