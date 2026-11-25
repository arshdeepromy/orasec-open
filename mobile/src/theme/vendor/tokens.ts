/**
 * Design tokens for every OraSign appearance — the single source of truth.
 *
 * Values come from the approved design canvas (ThemedDashboard `renderVals()` for the eight
 * styled looks; Main + Tokens for the flat OraFlows default). `render-css.ts` turns them into
 * `packages/ui/styles/appearances.css` (one block of CSS custom properties per appearance,
 * selected by `<html data-appearance="…">`), and `appearance.test.ts` checks the WCAG AA
 * contrast of every text/background pair and that the generated CSS is up to date.
 *
 * Colours that feed the shadcn tokens must be opaque hex (they become `H S% L%` channels);
 * the `style` group holds full CSS values (shadows, gradients, translucent panels, fonts).
 */
import type { AppearanceId } from './constants';
import { blend, mix, withAlpha } from './color';

export type StatusPair = { fg: string; bg: string };

export type AppearanceTokens = {
  /** Dark surfaces: `class="dark"` + `color-scheme: dark`. */
  isDark: boolean;

  /* ---- shadcn / Tailwind colour tokens (opaque hex) ---- */
  background: string;
  foreground: string;
  /** Opaque panel colour (`bg-card`); translucent panels use `style.surface`. */
  card: string;
  cardForeground: string;
  popover: string;
  popoverForeground: string;
  primary: string;
  primaryForeground: string;
  secondary: string;
  secondaryForeground: string;
  muted: string;
  mutedForeground: string;
  accent: string;
  accentForeground: string;
  destructive: string;
  destructiveForeground: string;
  border: string;
  input: string;
  ring: string;
  /** OraSign brand accent (gold): Sign / AI fills. Always carries `brandForeground` text. */
  brand: string;
  brandForeground: string;
  /** Gold-family text that is readable on panels (AI labels). */
  goldText: string;
  link: string;
  ok: StatusPair;
  warn: StatusPair;
  info: StatusPair;
  danger: StatusPair;
  neutral: StatusPair;
  chart: [string, string, string, string, string];
  track: string;
  envelopeEditorBackground: string;

  sidebar: {
    /** Opaque approximation of the rail (contrast tests, `--sb-bg`). */
    solid: string;
    text: string;
    textStrong: string;
    muted: string;
    activeText: string;
  };

  /* ---- style tokens (full CSS values) ---- */
  style: {
    pageBg: string;
    surface: string;
    well: string;
    panelBorder: string;
    panelBorderWidth: string;
    inputBg: string;
    inputBorder: string;
    inputShadow: string;
    buttonBg: string;
    buttonBorder: string;
    buttonBorderWidth: string;
    buttonShadow: string;
    primaryShadow: string;
    raised: string;
    raisedSm: string;
    raisedXs: string;
    inset: string;
    insetSm: string;
    insetXs: string;
    popoverShadow: string;
    blur: string;
    /** Base radius (`--radius`): controls. */
    radius: string;
    radiusCard: string;
    radiusPill: string;
    fontSans: string;
    fontHeading: string;
    fontNumber: string;
    headingCase: string;
    headingTracking: string;
    sidebarBg: string;
    sidebarBorder: string;
    sidebarShadow: string;
    sidebarGap: string;
    sidebarRadius: string;
    sidebarHover: string;
    sidebarActiveBg: string;
    sidebarActiveShadow: string;
    sidebarMarker: string;
    sidebarWell: string;
    stripe: string;
    stripeHeight: string;
    logoBg: string;
    logoInk: string;
    logoShadow: string;
    selectedBg: string;
    selectedShadow: string;
    meter: string;
    topbarBg: string;
    topbarBorder: string;
  };
};

const PLEX_SANS = "'IBM Plex Sans', 'Inter', system-ui, -apple-system, sans-serif";
const PLEX_SERIF = "'IBM Plex Serif', Georgia, serif";
const ZILLA = "'Zilla Slab', 'IBM Plex Serif', Georgia, serif";
const BRAND_GRADIENT = 'linear-gradient(115deg,#00A890 0%,#3FB86E 46%,#D8A800 100%)';
const NO_SHADOW = '0 0 #0000';

const shadow = (lo: string, hi: string, distance: number, blurPx: number) =>
  `${distance}px ${distance}px ${blurPx}px ${lo}, -${distance}px -${distance}px ${blurPx}px ${hi}`;

const insetShadow = (lo: string, hi: string, distance: number, blurPx: number) =>
  `inset ${distance}px ${distance}px ${blurPx}px ${lo}, inset -${distance}px -${distance}px ${blurPx}px ${hi}`;

type NeuInput = {
  base: string;
  hi: string;
  lo: string;
  text: string;
  muted: string;
  link: string;
  brand: string;
  brandForeground: string;
  goldText: string;
  primary: string;
  primaryForeground: string;
  active: string;
  chart1: string;
  chart2: string;
  track: string;
  destructive: string;
  destructiveForeground: string;
  isDark: boolean;
  chips: { done: StatusPair; waiting: StatusPair; viewed: StatusPair; overdue: StatusPair; draft: StatusPair };
};

/** Dark-surface chips from the design are translucent; flatten them onto the surface. */
const flattenChips = (chips: NeuInput['chips'], base: string): NeuInput['chips'] => {
  const flat = (pair: StatusPair): StatusPair => ({ fg: pair.fg, bg: blend(pair.bg, base) });

  return {
    done: flat(chips.done),
    waiting: flat(chips.waiting),
    viewed: flat(chips.viewed),
    overdue: flat(chips.overdue),
    draft: flat(chips.draft),
  };
};

/**
 * Soft UI (neumorphic) recipe from the design: page, panels and controls share ONE colour
 * and are separated by dual light/dark shadows; wells and inputs are inset.
 */
const neumorphic = (input: NeuInput): AppearanceTokens => {
  const { base, hi, lo } = input;
  const chips = flattenChips(input.chips, base);
  const subtle = mix(base, lo, 0.25);
  const line = mix(base, lo, 0.6);

  return {
    isDark: input.isDark,
    background: base,
    foreground: input.text,
    card: base,
    cardForeground: input.text,
    popover: base,
    popoverForeground: input.text,
    primary: input.primary,
    primaryForeground: input.primaryForeground,
    secondary: base,
    secondaryForeground: input.text,
    muted: subtle,
    mutedForeground: input.muted,
    accent: subtle,
    accentForeground: input.text,
    destructive: input.destructive,
    destructiveForeground: input.destructiveForeground,
    border: line,
    input: line,
    ring: input.active,
    brand: input.brand,
    brandForeground: input.brandForeground,
    goldText: input.goldText,
    link: input.link,
    ok: chips.done,
    warn: chips.waiting,
    info: chips.viewed,
    danger: chips.overdue,
    neutral: chips.draft,
    chart: [input.chart1, input.chart2, input.brand, chips.viewed.fg, chips.overdue.fg],
    track: input.track,
    envelopeEditorBackground: base,
    sidebar: {
      solid: base,
      text: input.text,
      textStrong: input.text,
      muted: input.muted,
      activeText: input.active,
    },
    style: {
      pageBg: base,
      surface: base,
      well: base,
      panelBorder: 'transparent',
      panelBorderWidth: '0px',
      inputBg: base,
      inputBorder: 'transparent',
      inputShadow: insetShadow(lo, hi, 4, 8),
      buttonBg: base,
      buttonBorder: 'transparent',
      buttonBorderWidth: '0px',
      buttonShadow: shadow(lo, hi, 4, 10),
      primaryShadow: shadow(lo, hi, 4, 10),
      raised: shadow(lo, hi, 8, 18),
      raisedSm: shadow(lo, hi, 5, 12),
      raisedXs: shadow(lo, hi, 3, 7),
      inset: insetShadow(lo, hi, 5, 10),
      insetSm: insetShadow(lo, hi, 3, 7),
      insetXs: insetShadow(lo, hi, 2, 4),
      popoverShadow: shadow(lo, hi, 8, 18),
      blur: 'none',
      radius: '0.875rem',
      radiusCard: '24px',
      radiusPill: '999px',
      fontSans: PLEX_SANS,
      fontHeading: PLEX_SANS,
      fontNumber: PLEX_SANS,
      headingCase: 'none',
      headingTracking: '-0.01em',
      sidebarBg: base,
      sidebarBorder: 'transparent',
      sidebarShadow: shadow(lo, hi, 10, 24),
      sidebarGap: '16px',
      sidebarRadius: '24px',
      sidebarHover: withAlpha(lo, 0.18),
      sidebarActiveBg: 'transparent',
      sidebarActiveShadow: insetShadow(lo, hi, 5, 10),
      sidebarMarker: 'transparent',
      sidebarWell: insetShadow(lo, hi, 4, 9),
      stripe: 'none',
      stripeHeight: '0px',
      logoBg: BRAND_GRADIENT,
      logoInk: '#FFFFFF',
      logoShadow: shadow(lo, hi, 5, 12),
      selectedBg: base,
      selectedShadow: shadow(lo, hi, 3, 7),
      meter: BRAND_GRADIENT,
      topbarBg: base,
      topbarBorder: 'transparent',
    },
  };
};

const DARK_CHIPS = {
  done: { bg: '#6EE0A824', fg: '#7FE6B2' },
  waiting: { bg: '#F2C14E24', fg: '#F2C94A' },
  viewed: { bg: '#8FB0FF24', fg: '#AFC4FF' },
  overdue: { bg: '#FF8C7A24', fg: '#FFA394' },
  draft: { bg: '#FFFFFF14', fg: '#C9D3DD' },
};

const oraflows: AppearanceTokens = {
  isDark: false,
  background: '#F5F6F8',
  foreground: '#0B1220',
  card: '#FFFFFF',
  cardForeground: '#0B1220',
  popover: '#FFFFFF',
  popoverForeground: '#0B1220',
  // Design teal-deep #007D6E was 4.27:1 as text on its own 12 % tint — #00705F passes AA.
  primary: '#00705F',
  primaryForeground: '#FFFFFF',
  secondary: '#EEF1F6',
  secondaryForeground: '#0B1220',
  muted: '#EEF1F6',
  mutedForeground: '#5B6577',
  accent: '#EEF1F6',
  accentForeground: '#0B1220',
  destructive: '#C8412F',
  destructiveForeground: '#FFFFFF',
  border: '#E5E9F0',
  input: '#D7DCE3',
  ring: '#00705F',
  brand: '#D8A800',
  brandForeground: '#0B1220',
  goldText: '#7A5E00',
  link: '#007A6B',
  ok: { fg: '#17704A', bg: '#E4F4EC' },
  warn: { fg: '#8F5A0A', bg: '#FBEFD9' },
  info: { fg: '#2350C8', bg: '#EEF2FE' },
  danger: { fg: '#A8321F', bg: '#FBE7E3' },
  neutral: { fg: '#4A5466', bg: '#EEF1F6' },
  chart: ['#00A890', '#0B1220', '#D8A800', '#2456E6', '#8A93A3'],
  track: '#EEF1F6',
  envelopeEditorBackground: '#F7F9FC',
  sidebar: {
    solid: '#0B1220',
    text: blend('#FFFFFFB3', '#0B1220'),
    textStrong: '#FFFFFF',
    muted: blend('#FFFFFF8C', '#0B1220'),
    activeText: '#FFFFFF',
  },
  style: {
    pageBg: '#F5F6F8',
    surface: '#FFFFFF',
    well: '#F7F9FC',
    panelBorder: '#E5E9F0',
    panelBorderWidth: '1px',
    inputBg: '#FFFFFF',
    inputBorder: '#D7DCE3',
    inputShadow: NO_SHADOW,
    buttonBg: '#FFFFFF',
    buttonBorder: '#D7DCE3',
    buttonBorderWidth: '1px',
    buttonShadow: NO_SHADOW,
    primaryShadow: NO_SHADOW,
    raised: '0 2px 4px rgba(16,24,40,.05), 0 12px 30px -16px rgba(16,24,40,.16)',
    raisedSm: '0 1px 2px rgba(16,24,40,.06)',
    raisedXs: NO_SHADOW,
    inset: 'inset 0 0 0 1px #E5E9F0',
    insetSm: 'inset 0 0 0 1px #E5E9F0',
    insetXs: NO_SHADOW,
    popoverShadow: '0 30px 70px -24px rgba(4,10,26,.30), 0 6px 18px -6px rgba(4,10,26,.18)',
    blur: 'none',
    radius: '0.6875rem',
    radiusCard: '14px',
    radiusPill: '8px',
    fontSans: PLEX_SANS,
    fontHeading: PLEX_SANS,
    fontNumber: PLEX_SANS,
    headingCase: 'none',
    headingTracking: '-0.01em',
    sidebarBg: '#0B1220',
    sidebarBorder: '#1A2232',
    sidebarShadow: NO_SHADOW,
    sidebarGap: '0px',
    sidebarRadius: '0px',
    sidebarHover: '#FFFFFF0F',
    sidebarActiveBg: '#FFFFFF14',
    sidebarActiveShadow: 'inset 3px 0 0 #3ED6BC',
    sidebarMarker: '#3ED6BC',
    sidebarWell: 'inset 0 0 0 1px #FFFFFF1F',
    stripe: 'none',
    stripeHeight: '0px',
    logoBg: BRAND_GRADIENT,
    logoInk: '#FFFFFF',
    logoShadow: NO_SHADOW,
    selectedBg: '#FFFFFF',
    selectedShadow: '0 1px 2px rgba(16,24,40,.1)',
    meter: BRAND_GRADIENT,
    topbarBg: '#FFFFFF',
    topbarBorder: '#E5E9F0',
  },
};

const velvet = neumorphic({
  isDark: true,
  base: '#1F3D35',
  hi: '#2B5347',
  lo: '#112420',
  text: '#EEF6F2',
  muted: '#A9C2B8',
  link: '#7FE6CF',
  brand: '#D8A800',
  brandForeground: '#14110A',
  goldText: '#F0C94A',
  primary: '#3ED6BC',
  primaryForeground: '#05231D',
  active: '#F0C94A',
  chart1: '#3ED6BC',
  chart2: '#7E9A8F',
  track: '#16302A',
  destructive: '#FF8C7A',
  destructiveForeground: '#2A0B05',
  chips: DARK_CHIPS,
});

const dark = neumorphic({
  isDark: true,
  base: '#171C25',
  hi: '#222937',
  lo: '#0B0E14',
  text: '#E8ECF2',
  muted: '#9AA4B5',
  link: '#3ED6BC',
  brand: '#F0C000',
  brandForeground: '#14110A',
  goldText: '#F0C94A',
  primary: '#3ED6BC',
  primaryForeground: '#04211C',
  active: '#3ED6BC',
  chart1: '#3ED6BC',
  chart2: '#5D6779',
  track: '#10141B',
  destructive: '#FF8C7A',
  destructiveForeground: '#2A0B05',
  chips: DARK_CHIPS,
});

const comfort = neumorphic({
  isDark: false,
  base: '#EFE6D2',
  hi: '#FFF8E8',
  lo: '#CDBF9F',
  text: '#3B2F1E',
  muted: '#6B5B44',
  link: '#1F6E60',
  brand: '#D4A62A',
  brandForeground: '#2B2111',
  goldText: '#7A5A0C',
  primary: '#265E52',
  primaryForeground: '#FFF8E8',
  active: '#1F6E60',
  chart1: '#4C9A86',
  chart2: '#A89474',
  track: '#DCCFB3',
  destructive: '#A3412A',
  destructiveForeground: '#FFF8E8',
  chips: {
    done: { bg: '#DCE7D2', fg: '#2F5E3A' },
    waiting: { bg: '#F3DDB0', fg: '#7A4F0B' },
    viewed: { bg: '#DDE2EC', fg: '#2E4A8A' },
    overdue: { bg: '#F1D2C6', fg: '#8E3420' },
    draft: { bg: '#E2D7BF', fg: '#5A4B35' },
  },
});

const gold = neumorphic({
  isDark: false,
  base: '#D9B44A',
  hi: '#F2D06A',
  lo: '#B0902C',
  text: '#221A04',
  muted: '#4A3A0C',
  link: '#00483F',
  brand: '#1F3D35',
  brandForeground: '#F6E6B4',
  goldText: '#3A2D06',
  primary: '#00453C',
  primaryForeground: '#FFFFFF',
  active: '#00483F',
  chart1: '#00594D',
  chart2: '#8A6B12',
  track: '#C3A13C',
  // Design #8A2513 / #1E5A35 were 4.49 / 4.12:1 as text on the gold surface — deepened for AA.
  destructive: '#7E2010',
  destructiveForeground: '#FFFFFF',
  chips: {
    done: { bg: '#F3E3A8', fg: '#164A2B' },
    waiting: { bg: '#F3E3A8', fg: '#6B3E00' },
    viewed: { bg: '#F3E3A8', fg: '#22408E' },
    overdue: { bg: '#F3E3A8', fg: '#7E2010' },
    draft: { bg: '#E6C870', fg: '#3A2D06' },
  },
});

const light = neumorphic({
  isDark: false,
  base: '#E9EDF2',
  hi: '#FFFFFF',
  lo: '#C3CAD5',
  text: '#0B1220',
  muted: '#4F596B',
  link: '#00705F',
  brand: '#D8A800',
  brandForeground: '#0B1220',
  goldText: '#6E5400',
  primary: '#006B5D',
  primaryForeground: '#FFFFFF',
  active: '#00705F',
  chart1: '#00A890',
  chart2: '#4F596B',
  track: '#D3D9E1',
  destructive: '#B23A2A',
  destructiveForeground: '#FFFFFF',
  chips: {
    done: { bg: '#DDF0E6', fg: '#17704A' },
    waiting: { bg: '#FBEFD9', fg: '#8F5A0A' },
    viewed: { bg: '#E3E9FB', fg: '#2350C8' },
    overdue: { bg: '#F7DFDA', fg: '#A8321F' },
    draft: { bg: '#DCE1E8', fg: '#3E4757' },
  },
});

// Vintage America: cream paper, navy + barn red, gold rules, slab-serif headings, offset print shadows.
const vintage: AppearanceTokens = {
  isDark: false,
  background: '#EFE5CC',
  foreground: '#1D2A44',
  card: '#F7F0DF',
  cardForeground: '#1D2A44',
  popover: '#FBF6EA',
  popoverForeground: '#1D2A44',
  primary: '#A3352A',
  primaryForeground: '#FFF8EA',
  secondary: '#F1E6CC',
  secondaryForeground: '#1D2A44',
  muted: '#F1E6CC',
  mutedForeground: '#5B4E3A',
  accent: '#E8DCC2',
  accentForeground: '#1D2A44',
  destructive: '#8E2A1F',
  destructiveForeground: '#FFF8EA',
  border: '#CDBB94',
  input: '#1D2A44',
  ring: '#1D2A44',
  brand: '#C9A227',
  brandForeground: '#1D2A44',
  goldText: '#7A5A0C',
  link: '#8E2A1F',
  ok: { fg: '#3E5A1E', bg: '#E3E6D0' },
  warn: { fg: '#7A4A00', bg: '#F1DFB2' },
  info: { fg: '#1D2A44', bg: '#DCE1EC' },
  danger: { fg: '#8E2A1F', bg: '#F2D3CC' },
  neutral: { fg: '#4A3D2A', bg: '#E8DCC2' },
  chart: ['#1D2A44', '#C9A227', '#B23A2E', '#3E5A1E', '#8A7A5C'],
  track: '#E3D6B8',
  envelopeEditorBackground: '#EFE5CC',
  sidebar: {
    solid: '#1D2A44',
    text: '#F7F0DF',
    textStrong: '#FFFFFF',
    muted: '#D9CBAE',
    activeText: '#F2D27A',
  },
  style: {
    pageBg: '#EFE5CC',
    surface: '#F7F0DF',
    well: '#F1E6CC',
    panelBorder: '#1D2A44',
    panelBorderWidth: '2px',
    inputBg: '#FBF6EA',
    inputBorder: '#1D2A44',
    inputShadow: 'inset 0 0 0 1px #CDBB94',
    buttonBg: '#F7F0DF',
    buttonBorder: '#1D2A44',
    buttonBorderWidth: '2px',
    buttonShadow: '3px 3px 0 #1D2A44',
    primaryShadow: '3px 3px 0 #1D2A44',
    raised: 'inset 0 0 0 3px #F7F0DF, inset 0 0 0 4px #C9A227, 4px 4px 0 #1D2A44',
    raisedSm: '3px 3px 0 #1D2A44',
    raisedXs: '2px 2px 0 #1D2A44',
    inset: 'inset 0 0 0 1px #CDBB94',
    insetSm: 'inset 0 0 0 1px #CDBB94',
    insetXs: NO_SHADOW,
    popoverShadow: '4px 4px 0 #1D2A44',
    blur: 'none',
    radius: '0.25rem',
    radiusCard: '6px',
    radiusPill: '3px',
    fontSans: PLEX_SERIF,
    fontHeading: ZILLA,
    fontNumber: ZILLA,
    headingCase: 'uppercase',
    headingTracking: '0.06em',
    sidebarBg: '#1D2A44',
    sidebarBorder: '#1D2A44',
    sidebarShadow: '4px 4px 0 #8E2A1F',
    sidebarGap: '0px',
    sidebarRadius: '0px',
    sidebarHover: '#FFFFFF14',
    sidebarActiveBg: '#FFFFFF14',
    sidebarActiveShadow: 'inset 3px 0 0 #C9A227',
    sidebarMarker: '#C9A227',
    sidebarWell: 'inset 0 0 0 1px #FFFFFF33',
    stripe: 'repeating-linear-gradient(90deg,#B23A2E 0 18px,#F7F0DF 18px 36px)',
    stripeHeight: '10px',
    logoBg: '#B23A2E',
    logoInk: '#F7F0DF',
    logoShadow: 'inset 0 0 0 2px #C9A227',
    selectedBg: '#F7F0DF',
    selectedShadow: 'inset 0 0 0 2px #B23A2E',
    meter: '#B23A2E',
    topbarBg: '#F7F0DF',
    topbarBorder: '#1D2A44',
  },
};

// Corporate trust: white cards, navy rail, bank-style blue, square-ish corners, quiet shadows.
const corporate: AppearanceTokens = {
  isDark: false,
  background: '#F4F6FA',
  foreground: '#0A2540',
  card: '#FFFFFF',
  cardForeground: '#0A2540',
  popover: '#FFFFFF',
  popoverForeground: '#0A2540',
  primary: '#1849A9',
  primaryForeground: '#FFFFFF',
  secondary: '#EEF1F5',
  secondaryForeground: '#0A2540',
  muted: '#EEF1F5',
  mutedForeground: '#4B5B70',
  accent: '#EEF1F5',
  accentForeground: '#0A2540',
  destructive: '#B42E1E',
  destructiveForeground: '#FFFFFF',
  border: '#DCE3EC',
  input: '#CBD5E1',
  ring: '#1849A9',
  brand: '#007D6E',
  brandForeground: '#FFFFFF',
  goldText: '#1849A9',
  link: '#1849A9',
  ok: { fg: '#146C43', bg: '#E3F5EC' },
  warn: { fg: '#8A5300', bg: '#FFF3D6' },
  info: { fg: '#1849A9', bg: '#E5EDFC' },
  danger: { fg: '#A8321F', bg: '#FDE7E5' },
  neutral: { fg: '#3F4B5E', bg: '#EEF1F5' },
  chart: ['#1849A9', '#9AA8BB', '#007D6E', '#0A2540', '#C8412F'],
  track: '#E6EBF2',
  envelopeEditorBackground: '#F7F9FC',
  sidebar: {
    solid: '#0A2540',
    text: '#DCE3EC',
    textStrong: '#FFFFFF',
    muted: '#B6C2D2',
    activeText: '#FFFFFF',
  },
  style: {
    pageBg: '#F4F6FA',
    surface: '#FFFFFF',
    well: '#F7F9FC',
    panelBorder: '#DCE3EC',
    panelBorderWidth: '1px',
    inputBg: '#FFFFFF',
    inputBorder: '#CBD5E1',
    inputShadow: NO_SHADOW,
    buttonBg: '#FFFFFF',
    buttonBorder: '#CBD5E1',
    buttonBorderWidth: '1px',
    buttonShadow: '0 1px 2px rgba(10,37,64,.08)',
    primaryShadow: '0 1px 2px rgba(10,37,64,.08)',
    raised: '0 1px 2px rgba(10,37,64,.06), 0 8px 24px -12px rgba(10,37,64,.14)',
    raisedSm: '0 1px 2px rgba(10,37,64,.08)',
    raisedXs: NO_SHADOW,
    inset: 'inset 0 0 0 1px #DCE3EC',
    insetSm: 'inset 0 0 0 1px #E3E8EF',
    insetXs: NO_SHADOW,
    popoverShadow: '0 12px 32px -12px rgba(10,37,64,.25), 0 2px 6px rgba(10,37,64,.08)',
    blur: 'none',
    radius: '0.5rem',
    radiusCard: '10px',
    radiusPill: '6px',
    fontSans: PLEX_SANS,
    fontHeading: PLEX_SANS,
    fontNumber: PLEX_SANS,
    headingCase: 'none',
    headingTracking: '-0.01em',
    sidebarBg: '#0A2540',
    sidebarBorder: '#0A2540',
    sidebarShadow: NO_SHADOW,
    sidebarGap: '0px',
    sidebarRadius: '0px',
    sidebarHover: '#FFFFFF12',
    sidebarActiveBg: '#FFFFFF1A',
    sidebarActiveShadow: 'inset 3px 0 0 #3ED6BC',
    sidebarMarker: '#3ED6BC',
    sidebarWell: 'inset 0 0 0 1px #FFFFFF26',
    stripe: 'none',
    stripeHeight: '0px',
    logoBg: '#1849A9',
    logoInk: '#FFFFFF',
    logoShadow: NO_SHADOW,
    selectedBg: '#FFFFFF',
    selectedShadow: '0 1px 2px rgba(10,37,64,.12), inset 0 0 0 1px #CBD5E1',
    meter: '#1849A9',
    topbarBg: '#FFFFFF',
    topbarBorder: '#DCE3EC',
  },
};

// Glassmorphism: frosted dark panels over the OraFlows teal / gold / blue glow.
const GLASS_PANEL = 'rgba(16,26,44,0.55)';
const GLASS_PAGE_SOLID = '#0B1220';
const glass: AppearanceTokens = {
  isDark: true,
  background: GLASS_PAGE_SOLID,
  foreground: '#F2F6FA',
  card: '#121C2F',
  cardForeground: '#F2F6FA',
  popover: '#131E33',
  popoverForeground: '#F2F6FA',
  primary: '#3ED6BC',
  primaryForeground: '#04211C',
  secondary: '#1C2840',
  secondaryForeground: '#F2F6FA',
  muted: '#1A2539',
  mutedForeground: '#BCC6D5',
  accent: '#22304A',
  accentForeground: '#F2F6FA',
  destructive: '#FF8C7A',
  destructiveForeground: '#2A0B05',
  border: '#2C3850',
  input: '#34415A',
  ring: '#7FE6CF',
  brand: '#F0C000',
  brandForeground: '#14110A',
  goldText: '#F0C94A',
  link: '#7FE6CF',
  ok: { fg: '#7FE6B2', bg: blend('#6EE0A824', '#121C2F') },
  warn: { fg: '#F2C94A', bg: blend('#F2C14E24', '#121C2F') },
  info: { fg: '#AFC4FF', bg: blend('#8FB0FF24', '#121C2F') },
  danger: { fg: '#FFA394', bg: blend('#FF8C7A24', '#121C2F') },
  neutral: { fg: '#C9D3DD', bg: blend('#FFFFFF14', '#121C2F') },
  chart: ['#3ED6BC', '#8C97A8', '#F0C000', '#7FA2FF', '#FF8C7A'],
  track: '#26324A',
  envelopeEditorBackground: '#0E1626',
  sidebar: {
    solid: '#121C2F',
    text: '#F2F6FA',
    textStrong: '#FFFFFF',
    muted: '#BCC6D5',
    activeText: '#7FE6CF',
  },
  style: {
    pageBg:
      'radial-gradient(circle at 12% 18%, rgba(0,168,144,.60), rgba(0,0,0,0) 38%), radial-gradient(circle at 88% 12%, rgba(216,168,0,.45), rgba(0,0,0,0) 34%), radial-gradient(circle at 72% 88%, rgba(36,86,230,.50), rgba(0,0,0,0) 42%), radial-gradient(circle at 30% 80%, rgba(63,184,110,.35), rgba(0,0,0,0) 36%), #0B1220',
    surface: GLASS_PANEL,
    well: 'rgba(255,255,255,0.06)',
    panelBorder: 'rgba(255,255,255,0.16)',
    panelBorderWidth: '1px',
    inputBg: 'rgba(16,26,44,0.55)',
    inputBorder: 'rgba(255,255,255,0.18)',
    inputShadow: NO_SHADOW,
    buttonBg: 'rgba(255,255,255,0.06)',
    buttonBorder: 'rgba(255,255,255,0.18)',
    buttonBorderWidth: '1px',
    buttonShadow: '0 4px 14px rgba(0,0,0,0.25)',
    primaryShadow: '0 4px 14px rgba(0,0,0,0.25)',
    raised: '0 10px 34px rgba(0,0,0,0.35), inset 0 1px 0 rgba(255,255,255,0.10)',
    raisedSm: '0 4px 14px rgba(0,0,0,0.25)',
    raisedXs: NO_SHADOW,
    inset: 'inset 0 0 0 1px rgba(255,255,255,0.12)',
    insetSm: 'inset 0 0 0 1px rgba(255,255,255,0.10)',
    insetXs: NO_SHADOW,
    popoverShadow: '0 18px 50px rgba(0,0,0,0.5)',
    blur: 'blur(18px) saturate(140%)',
    radius: '0.875rem',
    radiusCard: '22px',
    radiusPill: '999px',
    fontSans: PLEX_SANS,
    fontHeading: PLEX_SANS,
    fontNumber: PLEX_SANS,
    headingCase: 'none',
    headingTracking: '-0.01em',
    sidebarBg: GLASS_PANEL,
    sidebarBorder: 'rgba(255,255,255,0.16)',
    sidebarShadow: '0 10px 34px rgba(0,0,0,0.35)',
    sidebarGap: '16px',
    sidebarRadius: '22px',
    sidebarHover: 'rgba(255,255,255,0.07)',
    sidebarActiveBg: 'rgba(255,255,255,0.10)',
    sidebarActiveShadow: 'inset 0 0 0 1px rgba(255,255,255,0.18)',
    sidebarMarker: 'transparent',
    sidebarWell: 'inset 0 0 0 1px rgba(255,255,255,0.12)',
    stripe: 'none',
    stripeHeight: '0px',
    logoBg: BRAND_GRADIENT,
    logoInk: '#FFFFFF',
    logoShadow: '0 6px 18px rgba(0,168,144,0.45)',
    selectedBg: 'rgba(255,255,255,0.14)',
    selectedShadow: 'inset 0 0 0 1px rgba(255,255,255,0.3)',
    meter: BRAND_GRADIENT,
    topbarBg: 'rgba(16,26,44,0.45)',
    topbarBorder: 'rgba(255,255,255,0.12)',
  },
};

/*
 * OraFlows Navy — the brand look from the OraFlows / OraSign app icon: a deep navy base with a
 * teal and gold ribbon. Navy panels with a soft glossy top edge, teal actions, gold accents
 * (active item, focus, the brand stripe).
 */
const NAVY_BASE = '#081A40';
const NAVY_PANEL = '#10275A';

const navy: AppearanceTokens = {
  isDark: true,
  background: NAVY_BASE,
  foreground: '#F1F5FB',
  card: NAVY_PANEL,
  cardForeground: '#F1F5FB',
  popover: '#122C63',
  popoverForeground: '#F1F5FB',
  primary: '#34BFB2',
  primaryForeground: '#03202A',
  secondary: '#16305F',
  secondaryForeground: '#F1F5FB',
  muted: '#132C5C',
  mutedForeground: '#B4C2DA',
  accent: '#1A3668',
  accentForeground: '#F1F5FB',
  destructive: '#FF8C7A',
  destructiveForeground: '#2A0B05',
  border: '#25427A',
  input: '#2E4D86',
  ring: '#E9CF73',
  brand: '#D8B454',
  brandForeground: '#1A1405',
  goldText: '#E9CF73',
  link: '#6FDBCF',
  ok: { fg: '#7FE6B2', bg: blend('#6EE0A824', NAVY_PANEL) },
  warn: { fg: '#F2C94A', bg: blend('#F2C14E24', NAVY_PANEL) },
  info: { fg: '#AFC4FF', bg: blend('#8FB0FF24', NAVY_PANEL) },
  danger: { fg: '#FFA394', bg: blend('#FF8C7A24', NAVY_PANEL) },
  neutral: { fg: '#C9D3E3', bg: blend('#FFFFFF14', NAVY_PANEL) },
  chart: ['#34BFB2', '#8C9BB8', '#D8B454', '#7FA2FF', '#FF8C7A'],
  track: '#1A3466',
  envelopeEditorBackground: '#071533',
  sidebar: {
    solid: '#0A1D47',
    text: '#C9D4E8',
    textStrong: '#FFFFFF',
    muted: '#9DADC9',
    activeText: '#E9CF73',
  },
  style: {
    pageBg:
      'radial-gradient(circle at 8% 0%, rgba(52,191,178,.20), rgba(0,0,0,0) 40%), radial-gradient(circle at 96% 6%, rgba(216,180,84,.16), rgba(0,0,0,0) 36%), radial-gradient(circle at 50% 0%, rgba(30,62,128,.45), rgba(0,0,0,0) 60%), #081A40',
    surface: NAVY_PANEL,
    well: '#0B2050',
    panelBorder: 'rgba(255,255,255,0.08)',
    panelBorderWidth: '1px',
    inputBg: '#0A1D47',
    inputBorder: '#2E4D86',
    inputShadow: 'inset 0 1px 2px rgba(0,8,30,0.45)',
    buttonBg: '#152E62',
    buttonBorder: 'rgba(255,255,255,0.12)',
    buttonBorderWidth: '1px',
    buttonShadow: '0 2px 8px rgba(0,8,30,0.35), inset 0 1px 0 rgba(255,255,255,0.06)',
    primaryShadow: '0 6px 18px rgba(52,191,178,0.28)',
    raised: '0 10px 28px rgba(0,8,30,0.55), inset 0 1px 0 rgba(255,255,255,0.07)',
    raisedSm: '0 4px 14px rgba(0,8,30,0.45), inset 0 1px 0 rgba(255,255,255,0.06)',
    raisedXs: '0 1px 3px rgba(0,8,30,0.4)',
    inset: 'inset 0 1px 3px rgba(0,8,30,0.55)',
    insetSm: 'inset 0 1px 2px rgba(0,8,30,0.45)',
    insetXs: 'inset 0 1px 1px rgba(0,8,30,0.35)',
    popoverShadow: '0 18px 50px rgba(0,8,30,0.6)',
    blur: 'none',
    radius: '0.875rem',
    radiusCard: '20px',
    radiusPill: '999px',
    fontSans: PLEX_SANS,
    fontHeading: PLEX_SANS,
    fontNumber: PLEX_SANS,
    headingCase: 'none',
    headingTracking: '-0.01em',
    sidebarBg: '#0A1D47',
    sidebarBorder: 'rgba(255,255,255,0.08)',
    sidebarShadow: '0 10px 30px rgba(0,8,30,0.55)',
    sidebarGap: '16px',
    sidebarRadius: '20px',
    sidebarHover: 'rgba(255,255,255,0.06)',
    sidebarActiveBg: 'rgba(233,207,115,0.12)',
    sidebarActiveShadow: 'inset 3px 0 0 #E9CF73',
    sidebarMarker: '#E9CF73',
    sidebarWell: 'inset 0 1px 3px rgba(0,8,30,0.55)',
    stripe: 'linear-gradient(90deg, #34BFB2 0%, #D8B454 100%)',
    stripeHeight: '3px',
    logoBg: 'linear-gradient(160deg, #16306A 0%, #0A1D47 100%)',
    logoInk: '#E9CF73',
    logoShadow: '0 6px 18px rgba(0,8,30,0.5)',
    selectedBg: 'rgba(52,191,178,0.18)',
    selectedShadow: 'inset 0 0 0 1px rgba(52,191,178,0.55)',
    meter: 'linear-gradient(90deg, #34BFB2 0%, #D8B454 100%)',
    topbarBg: '#0A1D47',
    topbarBorder: 'rgba(255,255,255,0.08)',
  },
};

export const APPEARANCE_TOKENS: Record<AppearanceId, AppearanceTokens> = {
  oraflows,
  navy,
  velvet,
  dark,
  comfort,
  gold,
  light,
  vintage,
  corporate,
  glass,
};
