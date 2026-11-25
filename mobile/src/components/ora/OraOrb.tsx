/**
 * OraOrb — the owner-approved Ora character (gold ring, teal shape-shifting
 * body, gold eyes). Pure SVG + requestAnimationFrame; no animation library.
 *
 * Mobile port of frontend-v2/src/components/ora/OraOrb.tsx — the engine,
 * shapes, moods, colours and timing are identical on purpose (mobile parity).
 * Change both together.
 *
 * Engine
 *   • Six body shapes, each 26 numbers: `M x y` then four cubic `C` segments.
 *     The `working` mood cycles squircle→star→blob→tri→pill→circle, 620 ms per
 *     step, easeInOutCubic; every other mood eases the body back to `circle`.
 *   • The rAF loop writes attributes straight onto the SVG nodes (refs), so a
 *     frame never re-renders React. Mood changes re-render (eye markup only).
 *   • Moods: idle (breathe + blink every 5.2 s), listening (eyes look toward the
 *     input), working (morph, fast ring, squinting/scanning eyes), happy
 *     (bounce + smile arcs), sorry (tilt −12°, drooping eyes), sleeping (closed
 *     eyes, dim ring).
 *   • `prefers-reduced-motion: reduce` → one static frame, no rAF at all.
 *   • ids come from useId (one clipPath per instance); rAF cancelled on unmount.
 */
import { useEffect, useId, useRef } from 'react'

export type OraOrbMood = 'idle' | 'listening' | 'working' | 'happy' | 'sorry' | 'sleeping'

export interface OraOrbProps {
  mood?: OraOrbMood
  /** Rendered width/height in px. */
  size?: number
  className?: string
  /** Accessible name. Omit (or pass decorative) when a parent already labels it. */
  title?: string
  decorative?: boolean
}

/* ── Shapes ─────────────────────────────────────────────────────────── */

export const ORB_SHAPES = {
  circle: [60, 22, 81, 22, 98, 39, 98, 60, 98, 81, 81, 98, 60, 98, 39, 98, 22, 81, 22, 60, 22, 39, 39, 22, 60, 22],
  squircle: [60, 24, 90, 24, 96, 30, 96, 60, 96, 90, 90, 96, 60, 96, 30, 96, 24, 90, 24, 60, 24, 30, 30, 24, 60, 24],
  star: [60, 16, 68, 42, 78, 52, 104, 60, 78, 68, 68, 78, 60, 104, 52, 78, 42, 68, 16, 60, 42, 52, 52, 42, 60, 16],
  blob: [62, 20, 88, 24, 100, 42, 96, 62, 92, 86, 74, 100, 56, 96, 34, 92, 20, 78, 24, 56, 28, 36, 40, 18, 62, 20],
  tri: [60, 20, 74, 20, 90, 52, 99, 76, 104, 90, 96, 96, 60, 96, 24, 96, 16, 90, 21, 76, 30, 52, 46, 20, 60, 20],
  pill: [60, 30, 90, 30, 104, 42, 104, 60, 104, 78, 90, 90, 60, 90, 30, 90, 16, 78, 16, 60, 16, 42, 30, 30, 60, 30],
} as const satisfies Record<string, readonly number[]>

export type OrbShape = keyof typeof ORB_SHAPES

/** Working cycle order (from → to, 620 ms each, wraps). */
export const WORK_CYCLE: OrbShape[] = ['squircle', 'star', 'blob', 'tri', 'pill', 'circle']
export const MORPH_MS = 620
export const BLINK_EVERY_MS = 5200
const BLINK_MS = 150

export function easeInOutCubic(t: number): number {
  const x = Math.min(1, Math.max(0, t))
  return x < 0.5 ? 4 * x * x * x : 1 - Math.pow(-2 * x + 2, 3) / 2
}

export function lerpShape(a: readonly number[], b: readonly number[], t: number): number[] {
  const out = new Array<number>(26)
  for (let i = 0; i < 26; i++) out[i] = a[i] + (b[i] - a[i]) * t
  return out
}

/** 26 numbers → `M x y C … C … C … C …`. */
export function shapeToPath(n: readonly number[]): string {
  const f = (v: number) => (Math.round(v * 100) / 100).toString()
  let d = `M${f(n[0])} ${f(n[1])}`
  for (let s = 0; s < 4; s++) {
    const o = 2 + s * 6
    d += ` C${f(n[o])} ${f(n[o + 1])} ${f(n[o + 2])} ${f(n[o + 3])} ${f(n[o + 4])} ${f(n[o + 5])}`
  }
  return `${d} Z`
}

/** The body shape at `elapsed` ms into a working cycle. */
export function workingShapeAt(elapsed: number): number[] {
  const step = Math.floor(Math.max(0, elapsed) / MORPH_MS)
  const from = WORK_CYCLE[(step + WORK_CYCLE.length - 1) % WORK_CYCLE.length]
  const to = WORK_CYCLE[step % WORK_CYCLE.length]
  const p = easeInOutCubic((Math.max(0, elapsed) % MORPH_MS) / MORPH_MS)
  return lerpShape(ORB_SHAPES[from], ORB_SHAPES[to], p)
}

/* ── Per-mood constants ─────────────────────────────────────────────── */

const RING_SPEED: Record<OraOrbMood, number> = {
  idle: 0.05,
  listening: 0.08,
  working: 0.42,
  happy: 0.12,
  sorry: 0.02,
  sleeping: 0.01,
}
const SPARK_SPEED: Record<OraOrbMood, number> = {
  idle: 0.09,
  listening: 0.12,
  working: 0.3,
  happy: 0.2,
  sorry: 0.04,
  sleeping: 0,
}

const GOLD = '#D4AF37'
const SPARK = '#F5D76E'
const EYE = '#F5C542'
const EYE_STROKE = '#B8901F'
const CIRCLE_PATH = shapeToPath(ORB_SHAPES.circle)

function prefersReducedMotion(): boolean {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return false
  try {
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches
  } catch {
    return false
  }
}

/** Static eye geometry per mood (also the reduced-motion frame). */
function eyeBase(mood: OraOrbMood): { dx: number; dy: number; ry: number } {
  switch (mood) {
    case 'listening':
      return { dx: -1, dy: 2.5, ry: 6.6 }
    case 'working':
      return { dx: 0, dy: 0, ry: 4.2 }
    case 'sorry':
      return { dx: 0, dy: 3, ry: 5 }
    default:
      return { dx: 0, dy: 0, ry: 6.6 }
  }
}

export default function OraOrb({ mood = 'idle', size = 64, className, title = 'Ora', decorative = false }: OraOrbProps) {
  const rawId = useId()
  const uid = `ora${rawId.replace(/[^a-zA-Z0-9_-]/g, '')}`
  const clipId = `${uid}-clip`

  const moodRef = useRef<OraOrbMood>(mood)
  moodRef.current = mood

  const ringRef = useRef<SVGGElement>(null)
  const mainRingRef = useRef<SVGCircleElement>(null)
  const sparkRef = useRef<SVGGElement>(null)
  const bodyGroupRef = useRef<SVGGElement>(null)
  const bodyPathRef = useRef<SVGPathElement>(null)
  const clipPathRef = useRef<SVGPathElement>(null)
  const eyesRef = useRef<SVGGElement>(null)
  const eyeLRef = useRef<SVGEllipseElement>(null)
  const eyeRRef = useRef<SVGEllipseElement>(null)

  const reduced = prefersReducedMotion()

  useEffect(() => {
    if (reduced) return
    if (typeof window.requestAnimationFrame !== 'function') return

    let raf = 0
    let last = 0
    const start = performance.now()
    let ring = 0
    let spark = 0
    let tilt = 0
    let workingSince = -1
    let shape: number[] = [...ORB_SHAPES.circle]

    const frame = (now: number) => {
      const m = moodRef.current
      const dt = last ? Math.min(64, now - last) : 16
      last = now
      const t = now - start

      ring = (ring + RING_SPEED[m] * dt) % 360
      spark = (spark + SPARK_SPEED[m] * dt) % 360

      // Body shape: cycle while working, otherwise ease back to the circle.
      if (m === 'working') {
        if (workingSince < 0) workingSince = now
        shape = workingShapeAt(now - workingSince)
      } else {
        workingSince = -1
        const k = 1 - Math.pow(0.82, dt / 16)
        shape = lerpShape(shape, ORB_SHAPES.circle, k)
      }
      const d = shapeToPath(shape)
      bodyPathRef.current?.setAttribute('d', d)
      clipPathRef.current?.setAttribute('d', d)

      // Body transform: breathe / bounce / tilt.
      const targetTilt = m === 'sorry' ? -12 : 0
      tilt += (targetTilt - tilt) * Math.min(1, dt / 140)
      let scale = 1
      let dy = 0
      if (m === 'happy') {
        const b = Math.abs(Math.sin(t / 170))
        dy = -5 * b
        scale = 1 + 0.03 * b
      } else if (m === 'sleeping') {
        scale = 1 + 0.018 * Math.sin(t / 900)
        dy = -1.2 * Math.sin(t / 900)
      } else if (m !== 'working') {
        scale = 1 + 0.025 * Math.sin(t / 520)
        dy = -2 * Math.sin(t / 520)
      }
      bodyGroupRef.current?.setAttribute(
        'transform',
        `translate(0 ${dy.toFixed(2)}) rotate(${tilt.toFixed(2)} 60 60) translate(60 60) scale(${scale.toFixed(4)}) translate(-60 -60)`,
      )

      ringRef.current?.setAttribute('transform', `rotate(${ring.toFixed(2)} 60 60)`)
      sparkRef.current?.setAttribute('transform', `rotate(${spark.toFixed(2)} 60 60)`)

      // Eyes: blink (idle / listening / sorry), scan while working.
      const base = eyeBase(m)
      let ry = base.ry
      let dx = base.dx
      if (m === 'idle' || m === 'listening' || m === 'sorry') {
        if (t % BLINK_EVERY_MS < BLINK_MS) ry = 0.6
      }
      if (m === 'working') dx = 3 * Math.sin(t / 190)
      eyesRef.current?.setAttribute('transform', `translate(${dx.toFixed(2)} ${base.dy})`)
      eyeLRef.current?.setAttribute('ry', ry.toFixed(2))
      eyeRRef.current?.setAttribute('ry', ry.toFixed(2))

      raf = window.requestAnimationFrame(frame)
    }

    raf = window.requestAnimationFrame(frame)
    return () => window.cancelAnimationFrame(raf)
  }, [reduced])

  const base = eyeBase(mood)
  // Static frame (reduced motion, and the first paint before rAF runs).
  const staticShape = reduced && mood === 'working' ? shapeToPath(ORB_SHAPES.squircle) : CIRCLE_PATH
  const staticTilt = mood === 'sorry' ? 'rotate(-12 60 60)' : undefined
  const sleeping = mood === 'sleeping'

  return (
    <svg
      viewBox="0 0 120 120"
      width={size}
      height={size}
      className={className}
      role={decorative ? undefined : 'img'}
      aria-label={decorative ? undefined : title}
      aria-hidden={decorative ? true : undefined}
      data-mood={mood}
      data-reduced-motion={reduced ? 'true' : undefined}
      focusable="false"
    >
      <defs>
        <clipPath id={clipId} clipPathUnits="userSpaceOnUse">
          <path ref={clipPathRef} d={staticShape} data-testid="ora-orb-clip" />
        </clipPath>
      </defs>

      {/* Ring: faint base + rotating dashed main ring. */}
      <circle cx={60} cy={60} r={49} fill="none" stroke={GOLD} strokeWidth={3} opacity={sleeping ? 0.15 : 0.35} />
      <g ref={ringRef} opacity={sleeping ? 0.35 : 1}>
        <circle
          ref={mainRingRef}
          cx={60}
          cy={60}
          r={49}
          fill="none"
          stroke={GOLD}
          strokeWidth={3}
          strokeLinecap="round"
          strokeDasharray={mood === 'working' ? '16 10' : '230 78'}
          data-testid="ora-orb-ring"
        />
      </g>
      {!sleeping && (
        <g ref={sparkRef}>
          <circle cx={60} cy={11} r={2.6} fill={SPARK} />
        </g>
      )}

      {/* Body. */}
      <g ref={bodyGroupRef} transform={staticTilt}>
        <path ref={bodyPathRef} d={staticShape} fill="#00705F" data-testid="ora-orb-body" />
        <g clipPath={`url(#${clipId})`}>
          <circle cx={54} cy={50} r={31} fill="#00B39F" />
          <circle cx={47} cy={42} r={8} fill="#3ED6BC" opacity={0.6} />
        </g>

        <g ref={eyesRef} transform={`translate(${base.dx} ${base.dy})`} data-testid="ora-orb-eyes">
          {mood === 'happy' ? (
            <>
              <path d="M45 64 Q50 55 55 64" fill="none" stroke={EYE} strokeWidth={3.6} strokeLinecap="round" />
              <path d="M65 64 Q70 55 75 64" fill="none" stroke={EYE} strokeWidth={3.6} strokeLinecap="round" />
            </>
          ) : sleeping ? (
            <>
              <path d="M45.5 63 Q50 66 54.5 63" fill="none" stroke={EYE} strokeWidth={2} strokeLinecap="round" />
              <path d="M65.5 63 Q70 66 74.5 63" fill="none" stroke={EYE} strokeWidth={2} strokeLinecap="round" />
            </>
          ) : (
            <>
              <ellipse ref={eyeLRef} cx={50} cy={62} rx={4.6} ry={base.ry} fill={EYE} stroke={EYE_STROKE} strokeWidth={0.8} />
              <ellipse ref={eyeRRef} cx={70} cy={62} rx={4.6} ry={base.ry} fill={EYE} stroke={EYE_STROKE} strokeWidth={0.8} />
            </>
          )}
        </g>
      </g>
    </svg>
  )
}

