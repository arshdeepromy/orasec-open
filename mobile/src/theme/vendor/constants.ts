import { z } from 'zod';

/**
 * Appearances (visual themes) a customer can pick for OraSign.
 *
 * `oraflows` is the flat OraFlows look and the default for everyone. The order here is
 * the order shown in every switcher. Adding an appearance: add its id here, its tokens
 * in `packages/lib/universal/appearance/tokens.ts`, then regenerate
 * `packages/ui/styles/appearances.css` (see that file's header).
 */
export const APPEARANCE_IDS = [
  'oraflows',
  'navy',
  'velvet',
  'dark',
  'comfort',
  'gold',
  'light',
  'vintage',
  'corporate',
  'glass',
] as const;

export type AppearanceId = (typeof APPEARANCE_IDS)[number];

/** What a user can save: a fixed appearance, or `auto` (follow the device light/dark setting). */
export const APPEARANCE_PREFERENCES = [...APPEARANCE_IDS, 'auto'] as const;

export type AppearancePreference = (typeof APPEARANCE_PREFERENCES)[number];

export const DEFAULT_APPEARANCE: AppearanceId = 'oraflows';

/** `auto` maps a light device to this appearance… */
export const AUTO_LIGHT_APPEARANCE: AppearanceId = 'oraflows';

/** …and a dark device to this one. */
export const AUTO_DARK_APPEARANCE: AppearanceId = 'dark';

/** Appearances with dark surfaces: they also get `class="dark"` so `dark:` utilities apply. */
export const DARK_APPEARANCE_IDS: readonly AppearanceId[] = ['navy', 'velvet', 'dark', 'glass'];

/** Name of the (non-secret, unsigned) cookie that mirrors the preference for SSR and signed-out pages. */
export const APPEARANCE_COOKIE_NAME = 'orasign-appearance';

export const ZAppearanceIdSchema = z.enum(APPEARANCE_IDS);

export const ZAppearancePreferenceSchema = z.enum(APPEARANCE_PREFERENCES);

export const isAppearancePreference = (value: unknown): value is AppearancePreference =>
  ZAppearancePreferenceSchema.safeParse(value).success;

/**
 * Normalise any stored/cookie value to a valid preference. Unknown, empty or missing
 * values fall back to the default appearance (never throw: an old or tampered cookie
 * must not break a page).
 */
export const parseAppearancePreference = (value: unknown): AppearancePreference => {
  if (isAppearancePreference(value)) {
    return value;
  }

  return DEFAULT_APPEARANCE;
};

/**
 * Map a value of the legacy light/dark `theme` cookie (remix-themes, OraSign ≤ 3.11) to an
 * appearance, so existing dark-mode users keep a dark look after the upgrade.
 */
export const appearanceFromLegacyTheme = (theme: unknown): AppearancePreference | null => {
  if (theme === 'dark') {
    return 'dark';
  }

  if (theme === 'light') {
    return 'oraflows';
  }

  return null;
};

/** Resolve a preference to the appearance that is actually rendered. */
export const resolveAppearance = (preference: AppearancePreference, prefersDark: boolean): AppearanceId => {
  if (preference === 'auto') {
    return prefersDark ? AUTO_DARK_APPEARANCE : AUTO_LIGHT_APPEARANCE;
  }

  return preference;
};

export const isDarkAppearance = (appearance: AppearanceId) => DARK_APPEARANCE_IDS.includes(appearance);

/** The `class` for `<html>` rendered on the server (auto is resolved by CSS media queries). */
export const getAppearanceHtmlClass = (preference: AppearancePreference) => {
  if (preference === 'auto') {
    return '';
  }

  return isDarkAppearance(preference) ? 'dark' : '';
};
