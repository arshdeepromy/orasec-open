import {
  APPEARANCE_IDS,
  type AppearanceId,
  type AppearancePreference,
  DEFAULT_APPEARANCE,
  isAppearancePreference,
  resolveAppearance,
} from '@/theme/vendor/constants'
import { APPEARANCE_TOKENS, type AppearanceTokens } from '@/theme/vendor/tokens'

/**
 * The 9 OraSec appearances + Auto, from the web app's tokens
 * (packages/lib/universal/appearance/tokens.ts — the single source of truth;
 * imported as-is, never copied). Each appearance becomes the app's design-
 * system variables (src/index.css, shared with the publisher's invoicing app), so every
 * screen restyles from one place.
 *
 * Applied by `data-appearance` on <html> + the `dark` class for dark looks.
 */
export type { AppearanceId, AppearancePreference }
export { APPEARANCE_IDS, DEFAULT_APPEARANCE, isAppearancePreference, resolveAppearance }

export const APPEARANCE_LABELS: Record<AppearancePreference, string> = {
  auto: 'Auto',
  oraflows: 'OraFlows',
  navy: 'OraFlows Navy',
  velvet: 'Velvet',
  dark: 'Dark',
  comfort: 'Comfort',
  gold: 'Gold',
  light: 'Light',
  vintage: 'Vintage',
  corporate: 'Corporate',
  glass: 'Glass',
}

export const APPEARANCE_DESCRIPTIONS: Record<AppearancePreference, string> = {
  auto: 'Follows your phone: light → OraFlows, dark → Dark',
  oraflows: 'Clean and flat, navy and teal',
  navy: 'Deep navy with teal and gold accents',
  velvet: 'Dark velvet green, soft raised panels',
  dark: 'Dark, soft raised panels',
  comfort: 'Warm cream, easy on the eyes',
  gold: 'Gold, soft raised panels',
  light: 'Light grey, soft raised panels',
  vintage: 'Cream paper, navy and barn red',
  corporate: 'White cards, navy and blue',
  glass: 'Frosted dark panels with a glow',
}

/** The app's design-system variables for one appearance. Pure (unit-tested). */
export function mobileVariables(t: AppearanceTokens): Array<[string, string]> {
  const s = t.style
  return [
    ['color-scheme', t.isDark ? 'dark' : 'light'],

    // Brand / actions
    ['--accent', t.primary],
    ['--color-primary', t.primary],
    ['--color-secondary', t.secondary],
    ['--accent-fg', t.primary],
    ['--accent-on', t.primaryForeground],
    ['--accent-press', `color-mix(in srgb, ${t.primary} 84%, #000)`],
    ['--accent-soft', `color-mix(in srgb, ${t.primary} 14%, transparent)`],
    ['--brand', t.brand],
    ['--brand-on', t.brandForeground],
    ['--gold-text', t.goldText],
    ['--link', t.link],

    // Surfaces & text
    ['--ink', t.sidebar.solid],
    ['--canvas', t.background],
    ['--page-bg', s.pageBg],
    ['--card', s.surface],
    ['--card-solid', t.card],
    ['--card-2', t.muted],
    ['--well', s.well],
    ['--border', t.border],
    ['--border-strong', t.input],
    ['--panel-border', s.panelBorder],
    ['--panel-bw', s.panelBorderWidth],
    ['--text', t.foreground],
    ['--muted', t.mutedForeground],
    ['--muted-2', t.mutedForeground],
    ['--popover', t.popover],

    // Status (contrast-safe pairs from the tokens)
    ['--ok', t.ok.fg],
    ['--ok-soft', t.ok.bg],
    ['--warn', t.warn.fg],
    ['--warn-soft', t.warn.bg],
    ['--info', t.info.fg],
    ['--info-soft', t.info.bg],
    ['--danger', t.danger.fg],
    ['--danger-soft', t.danger.bg],
    ['--neutral', t.neutral.fg],
    ['--neutral-soft', t.neutral.bg],

    // Shape, depth, glass
    ['--r-card', s.radiusCard],
    ['--r-ctl', s.radius],
    ['--r-pill', s.radiusPill],
    ['--shadow-card', s.raised],
    ['--shadow-card-sm', s.raisedSm],
    ['--shadow-xs', s.raisedXs],
    ['--shadow-inset', s.inset],
    ['--shadow-inset-sm', s.insetSm],
    ['--shadow-pop', s.popoverShadow],
    ['--shadow-fab', s.primaryShadow],
    ['--blur', s.blur],

    // Controls
    ['--input-bg', s.inputBg],
    ['--input-border', s.inputBorder],
    ['--input-shadow', s.inputShadow],
    ['--button-bg', s.buttonBg],
    ['--button-border', s.buttonBorder],
    ['--button-bw', s.buttonBorderWidth],
    ['--button-shadow', s.buttonShadow],
    ['--selected-bg', s.selectedBg],
    ['--selected-shadow', s.selectedShadow],

    // Type
    ['--sans', s.fontSans],
    ['--heading', s.fontHeading],
    ['--number', s.fontNumber],
    ['--heading-case', s.headingCase],
    ['--heading-tracking', s.headingTracking],

    // Navigation (the web sidebar becomes the floating bottom bar)
    ['--nav-bg', s.sidebarBg],
    ['--nav-border', s.sidebarBorder],
    ['--nav-shadow', s.sidebarShadow],
    ['--nav-text', t.sidebar.text],
    ['--nav-text-strong', t.sidebar.textStrong],
    ['--nav-active-text', t.sidebar.activeText],
    ['--nav-active-bg', s.sidebarActiveBg],
    ['--nav-active-shadow', navActiveShadow(s.sidebarActiveShadow)],
    ['--nav-solid', t.sidebar.solid],

    // Header bar + accents
    ['--topbar-bg', s.topbarBg],
    ['--topbar-border', s.topbarBorder],
    ['--stripe', s.stripe],
    ['--stripe-h', s.stripeHeight],
    ['--logo-bg', s.logoBg],
    ['--logo-ink', s.logoInk],
    ['--logo-shadow', s.logoShadow],
    ['--meter', s.meter],
  ]
}

/**
 * The web sidebar marks the active item with a 3px bar on its left edge
 * (`inset 3px 0 0 <colour>`). On the rounded bottom-bar pills that reads as a
 * glitch, so it becomes a thin ring in the same colour. Other shadows (raised
 * / inset looks) are kept.
 */
export function navActiveShadow(shadow: string): string {
  const bar = /^inset\s+3px\s+0(?:px)?\s+0(?:px)?\s+(.+)$/.exec(shadow.trim())
  return bar ? `inset 0 0 0 1.5px ${bar[1]}` : shadow
}

/** One CSS block per appearance; the default also on :root (first paint). */
export function renderMobileAppearanceCss(): string {
  const blocks = APPEARANCE_IDS.map((id) => {
    const selector = id === DEFAULT_APPEARANCE ? `:root, :root[data-appearance="${id}"]` : `:root[data-appearance="${id}"]`
    const body = mobileVariables(APPEARANCE_TOKENS[id])
      .map(([k, v]) => `  ${k}: ${v};`)
      .join('\n')
    return `${selector} {\n${body}\n}`
  })
  // Brand surfaces (sign-in, PIN / lock screens) always wear the brand look,
  // whatever appearance the person picked — like the app icon and splash.
  const brand = mobileVariables(APPEARANCE_TOKENS[BRAND_APPEARANCE])
    .map(([k, v]) => `  ${k}: ${v};`)
    .join('\n')
  blocks.push(`${BRAND_SURFACE_SELECTOR} {\n${brand}\n}`)
  return blocks.join('\n\n')
}

/** Base tokens for the link and lock screens; index.css re-colours them to the OraSec console dark and teal. */
export const BRAND_APPEARANCE: AppearanceId = 'navy'
export const BRAND_SURFACE_SELECTOR = '.brand-surface, .lock-screen'

export function isDarkAppearanceId(id: AppearanceId): boolean {
  return APPEARANCE_TOKENS[id].isDark
}

export function tokensFor(id: AppearanceId): AppearanceTokens {
  return APPEARANCE_TOKENS[id]
}

const STYLE_ID = 'orasec-appearances'

/** Inject the appearance CSS once. */
export function installAppearanceCss(): void {
  if (typeof document === 'undefined' || document.getElementById(STYLE_ID)) return
  const el = document.createElement('style')
  el.id = STYLE_ID
  el.textContent = renderMobileAppearanceCss()
  document.head.appendChild(el)
}

/** Apply a resolved appearance to <html>. */
export function applyAppearance(id: AppearanceId): void {
  if (typeof document === 'undefined') return
  const root = document.documentElement
  root.dataset.appearance = id
  root.classList.toggle('dark', isDarkAppearanceId(id))
  const meta = document.querySelector('meta[name="theme-color"]')
  if (meta) meta.setAttribute('content', APPEARANCE_TOKENS[id].background)
}

/* ------------------------- local cache (no flash) ------------------------- */

const CACHE_KEY = 'orasec.appearance.v1'

/**
 * Synchronous read for first paint (localStorage survives in the WebView).
 * Nothing saved yet → Auto, so a fresh install follows the phone's light/dark.
 */
export function readCachedPreference(): AppearancePreference {
  try {
    const raw = globalThis.localStorage?.getItem(CACHE_KEY)
    return raw && isAppearancePreference(raw) ? raw : 'auto'
  } catch {
    return 'auto'
  }
}

export function writeCachedPreference(pref: AppearancePreference): void {
  try {
    globalThis.localStorage?.setItem(CACHE_KEY, pref)
  } catch {
    // ignore
  }
}

