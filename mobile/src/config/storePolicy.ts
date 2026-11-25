import { Capacitor } from '@capacitor/core'

/**
 * Store-policy guards (App Store 3.1.1 / 3.1.3, Google Play Payments policy).
 *
 * OraSec is an enterprise app: organisations buy OraSec on the web; members
 * only sign in here. So nothing the app shows may offer or point to buying —
 * no plan, pricing, upgrade, trial, subscription or "buy on the website" text,
 * including messages that come from the server (quota and feature errors say
 * "upgrade your plan" on the web). Same rules as the publisher's invoicing app
 * (Invoicing docs/RUNBOOKS/mobile-release.md "App Store rules the app follows").
 */

const COMMERCE_WORDS =
  /\b(upgrade|upgrading|subscri(?:be|ption|ptions)|pricing|price|plans?|billing|trial|purchase|buy|checkout|payment method|add-?ons?|top[ -]?up|credits?)\b/i

export const ORGANISATION_LIMIT_MESSAGE =
  "This isn't available for your organisation right now. Contact your organisation's administrator."

/** True when a message mentions plans, prices or buying. */
export function mentionsCommerce(text: string): boolean {
  return COMMERCE_WORDS.test(text)
}

/** A server/user-facing message, with any plan/upgrade wording replaced. */
export function storeSafeMessage(text: string): string {
  return mentionsCommerce(text) ? ORGANISATION_LIMIT_MESSAGE : text
}

/**
 * Legal pages open in app mode (`?app=1`: the document only, no site menu,
 * pricing or sign-up links).
 */
export function appModeUrl(url: string): string {
  return `${url}${url.includes('?') ? '&' : '?'}app=1`
}

/**
 * The terms describe plans and trials, so (like the publisher's invoicing app) the iOS app
 * doesn't link them. Android and the preview do.
 */
export function showTermsLink(): boolean {
  return Capacitor.getPlatform() !== 'ios'
}
