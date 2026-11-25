import { clearDeviceToken, getDeviceToken, notifyDeviceRejected } from '@/api/session'
import { getServerUrl } from '@/config/serverConfig'
import { isDemoCode, isDemoToken } from '@/demo/session'

/**
 * Low-level HTTP for the OraSec mobile API (`/api/v2/orasec/mobile/…`).
 * Every request carries `Authorization: Bearer <device token>` once the phone is linked.
 */
export const API_PREFIX = '/api/v2/orasec/mobile'

export class ApiError extends Error {
  readonly status: number
  readonly code: string

  constructor(opts: { status: number; code?: string; message?: string }) {
    super(opts.message || `Request failed (${opts.status})`)
    this.name = 'ApiError'
    this.status = opts.status
    this.code = opts.code || (opts.status === 0 ? 'network' : 'unknown')
  }

  get isNetworkError(): boolean {
    return this.status === 0
  }
}

export function apiUrl(path: string): string {
  return `${getServerUrl()}${API_PREFIX}${path}`
}

async function readError(response: Response): Promise<ApiError> {
  let body: Record<string, unknown> = {}
  try {
    body = (await response.json()) as Record<string, unknown>
  } catch {
    body = {}
  }
  const fallback =
    response.status === 403
      ? 'Your account does not have access to this.'
      : response.status >= 500
        ? 'OraSec had a problem. Try again in a moment.'
        : `Request failed (${response.status})`
  return new ApiError({
    status: response.status,
    code: typeof body.code === 'string' ? body.code : undefined,
    message: typeof body.error === 'string' ? body.error : typeof body.detail === 'string' ? body.detail : fallback,
  })
}

/** JSON request to the mobile API. Throws ApiError (status 0 when offline / unreachable). */
export async function api<T>(path: string, init: { method?: 'GET' | 'POST'; body?: unknown; signal?: AbortSignal } = {}): Promise<T> {
  const token = getDeviceToken()
  // Demo mode (App Review / screenshots): answered from bundled sample data, never sent to a server.
  if (isDemoToken(token) || (path === '/link/' && !token && (await isDemoCode((init.body as { code?: unknown } | undefined)?.code)))) {
    const { demoRequest } = await import('@/demo/demoApi')
    return demoRequest<T>(path, init)
  }
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (token) headers.Authorization = `Bearer ${token}`
  if (init.body !== undefined) headers['Content-Type'] = 'application/json'
  let response: Response
  try {
    response = await fetch(apiUrl(path), {
      method: init.method ?? 'GET',
      headers,
      body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
      signal: init.signal,
    })
    if (response.status === 429 && (init.method ?? 'GET') === 'GET') {
      await new Promise((resolve) => setTimeout(resolve, 2000))
      if (!init.signal?.aborted) {
        response = await fetch(apiUrl(path), { method: 'GET', headers, signal: init.signal })
      }
    }
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw error
    throw new ApiError({ status: 0, code: 'network', message: "Can't reach OraSec. Check your connection." })
  }
  if (response.status === 401 && token) {
    await clearDeviceToken()
    notifyDeviceRejected()
  }
  if (!response.ok && response.status !== 202) throw await readError(response)
  return (await response.json()) as T
}

/** Human message for any error thrown by the API layer. */
export function errorMessage(error: unknown, fallback = 'Something went wrong. Please try again.'): string {
  if (error instanceof ApiError) return error.message || fallback
  if (error instanceof Error && error.message) return error.message
  return fallback
}

