/**
 * Where to go after signing in: the screen that sent the user to /login
 * (a deep link, a signing link that needs an account, a push notification).
 * Kept in sessionStorage so it survives the 2FA step and the browser sign-in
 * round trip. Only in-app paths are accepted.
 */
const KEY = 'orasec.returnTo.v1' // gitleaks:allow (storage key name, not a secret)

const isSafePath = (p: unknown): p is string =>
  typeof p === 'string' && p.startsWith('/') && !p.startsWith('//') && !/^\/(login|two-factor|forgot-password|no-access)\b/.test(p)

export function rememberReturnTo(path: unknown): void {
  try {
    if (isSafePath(path)) sessionStorage.setItem(KEY, path)
  } catch {
    // Storage unavailable — fall back to Home.
  }
}

/** The remembered path (once), else Home. */
export function takeReturnTo(fallback = '/'): string {
  try {
    const p = sessionStorage.getItem(KEY)
    sessionStorage.removeItem(KEY)
    return isSafePath(p) ? p : fallback
  } catch {
    return fallback
  }
}

/** The remembered path without clearing it (for redirects that may race the sign-in screen). */
export function peekReturnTo(fallback = '/'): string {
  try {
    const p = sessionStorage.getItem(KEY)
    return isSafePath(p) ? p : fallback
  } catch {
    return fallback
  }
}
