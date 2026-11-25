/**
 * The few values that belong to whoever builds and publishes the app. Each can be set at build time
 * (see `.env.store.example`); the defaults are the ones of the published OraSec app.
 */
const env = import.meta.env as Record<string, string | undefined>

const value = (name: string, fallback: string): string => {
  const v = (env[name] ?? '').trim()
  return v || fallback
}

/** Who publishes this build (shown at the bottom of Settings). */
export const PUBLISHER = value('VITE_PUBLISHER', 'OraFlows Limited')

/** The app's privacy notice. */
export const PRIVACY_POLICY_URL = value('VITE_PRIVACY_URL', 'https://oraflows.co.nz/orasec-app-privacy/')

/**
 * Where the source code and the self-hosting guide live. Empty until the publisher sets it: the app then shows no
 * "Source code" and "Host your own" links (a link to a page that does not exist yet is worse than none).
 */
export const SOURCE_URL = value('VITE_SOURCE_URL', '')
