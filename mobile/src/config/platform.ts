import { Capacitor } from '@capacitor/core'

/**
 * Platform gates for the OraSec app.
 *
 * Store-policy rule (Apple 3.1.1 / Google Payments, same as the invoicing
 * app): subscriptions, plans, add-ons and AI-token purchases are sold on the
 * web only. The native app never shows signup, pricing, billing management,
 * "upgrade" buttons, or any pointer to buying on the website — not by link,
 * not by deep link, and never re-added over the air. Every such screen checks
 * `purchaseFlowsEnabled()`, which is false for every native build.
 */
export function isNativeApp(): boolean {
  return Capacitor.isNativePlatform()
}

/** Signup is web-only (the signup wizard takes card details through Stripe). */
export function signupEnabled(): boolean {
  return !isNativeApp()
}

/**
 * Billing / subscription / add-on / AI-token purchase screens and any upgrade
 * call-to-action. False on every native build; the mobile web preview shows
 * the same app as the stores, so it is false there too.
 */
export function purchaseFlowsEnabled(): boolean {
  return false
}
