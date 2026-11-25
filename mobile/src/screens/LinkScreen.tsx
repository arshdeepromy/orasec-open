import { Block, Page } from 'konsta/react'
import { type FormEvent, useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'

import { errorMessage } from '@/api/http'
import { BrandMark } from '@/components/BrandMark'
import ServerStep from '@/components/ServerStep'
import { PRIVACY_POLICY_URL } from '@/config/brand'
import { getDisplayServerUrl, hasServer, webAppUrl } from '@/config/serverConfig'
import { useAuth } from '@/contexts/AuthContext'
import { useLayout } from '@/hooks/useLayout'
import { takeReturnTo } from '@/navigation/returnTo'
import { openExternalUrl } from '@/native/browser'
import { takeSignInNotice } from '@/security/appPin'

/** Formats what the person types as XXXXX-XXXXX (letters and digits only, no 0/O/1/I confusion on the server). */
export function formatCode(input: string): string {
  const raw = input.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 10)
  return raw.length > 5 ? `${raw.slice(0, 5)}-${raw.slice(5)}` : raw
}

/**
 * Link this phone to an OraSec server.
 *
 * Step 1: the address of the organisation's OraSec server (kept on the device, can be changed here).
 * Step 2: there is no password in the app. The person creates a one-time code in the OraSec web app, enters it
 * here, and the server issues a device token.
 */
export default function LinkScreen() {
  const { link, startDemo, signedOutReason } = useAuth()
  const navigate = useNavigate()
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const { isTablet } = useLayout()
  const thing = isTablet ? 'tablet' : 'phone'
  // Which server: asked first when the app does not know one, and again when the person taps "Change".
  const [serverKnown, setServerKnown] = useState(hasServer())
  const [changing, setChanging] = useState(false)
  const askServer = !serverKnown || changing

  useEffect(() => {
    setNotice(takeSignInNotice() ?? signedOutReason)
  }, [signedOutReason])

  const ready = code.replace('-', '').length === 10 && !busy

  const submit = async (e?: FormEvent) => {
    e?.preventDefault()
    if (!ready) return
    setBusy(true)
    setError(null)
    try {
      await link(code)
      navigate(takeReturnTo(), { replace: true })
    } catch (err) {
      setError(errorMessage(err, 'Linking failed. Create a new code in OraSec and try again.'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Page className="bg-[var(--card-solid)]">
      <div className="auth-hero bg-[var(--ink)] px-6 pb-10 pt-16 text-center">
        <BrandMark size={80} className="mx-auto mb-3 shadow-lg shadow-black/30" />
        <h1 className="text-2xl font-bold tracking-tight text-[var(--nav-text-strong)]">OraSec</h1>
        <p className="mt-1 text-sm text-[var(--nav-text)]">Security operations, by OraFlows</p>
      </div>

      <Block className="-mt-4 rounded-t-2xl bg-[var(--card-solid)] pt-6">
        {notice && !error ? (
          <div role="status" className="mb-4 rounded-lg bg-[var(--warn-soft)] px-4 py-3 text-sm text-[var(--text)]" data-testid="link-notice">
            {notice}
          </div>
        ) : null}
        {error ? (
          <div role="alert" className="mb-4 rounded-lg bg-[var(--danger-soft)] px-4 py-3 text-sm text-[var(--danger)]" data-testid="link-error">
            {error}
          </div>
        ) : null}

        {askServer ? (
          <ServerStep
            initial={serverKnown ? getDisplayServerUrl() : ''}
            onDone={() => {
              setServerKnown(true)
              setChanging(false)
              setCode('')
              setError(null)
              setNotice(null)
            }}
            onCancel={serverKnown ? () => setChanging(false) : undefined}
          />
        ) : (
          <>
            <div className="mb-5 flex items-center justify-between gap-3 rounded-xl border border-[var(--border)] px-4 py-3" data-testid="server-row">
              <div className="min-w-0">
                <div className="text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">Server</div>
                <div className="truncate text-sm font-medium text-[var(--text)]" data-testid="server-name">{getDisplayServerUrl()}</div>
              </div>
              <button type="button" className="text-sm font-semibold text-[var(--accent)]" onClick={() => setChanging(true)} data-testid="server-change">
                Change
              </button>
            </div>

            <h2 className="text-lg font-semibold text-[var(--text)]">Link this {thing}</h2>
            <ol className="hint-steps mb-5">
              <li>
                Open OraSec on your computer and choose <b>Profile menu → Mobile app</b>.
              </li>
              <li>Create a link code and type it below. It works once and expires in 10 minutes.</li>
            </ol>

            <form onSubmit={(e) => void submit(e)} noValidate>
              <label htmlFor="link-code" className="mb-1.5 block text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
                Link code
              </label>
              <input
                id="link-code"
                data-testid="link-code"
                className="input link-code"
                value={code}
                onChange={(e) => setCode(formatCode(e.target.value))}
                placeholder="XXXXX-XXXXX"
                autoCapitalize="characters"
                autoComplete="one-time-code"
                autoCorrect="off"
                spellCheck={false}
                inputMode="text"
                maxLength={11}
              />
              <button type="submit" className="btn btn-primary mt-5" disabled={!ready} data-testid="link-submit">
                {busy ? 'Linking…' : `Link ${thing}`}
              </button>
            </form>

            <button type="button" className="btn btn-ghost mt-3" onClick={() => void openExternalUrl(webAppUrl('/orasec/mobile/'))}>
              Open OraSec on the web
            </button>
          </>
        )}

        <div className="mt-6 rounded-xl border border-[var(--border)] px-4 py-4 text-center" data-testid="demo-card">
          <p className="text-sm font-semibold text-[var(--text)]">No OraSec account?</p>
          <p className="mt-1 text-xs leading-relaxed text-[var(--muted)]">Try the app with sample data. Nothing is sent anywhere.</p>
          <button
            type="button"
            className="btn btn-primary mt-3"
            disabled={busy}
            data-testid="try-demo"
            onClick={async () => {
              setBusy(true)
              setError(null)
              try {
                await startDemo()
                navigate('/', { replace: true })
              } catch (err) {
                setError(errorMessage(err))
              } finally {
                setBusy(false)
              }
            }}
          >
            Try the demo
          </button>
        </div>

        <p className="mt-6 text-center text-xs leading-relaxed text-[var(--muted)]">
          {askServer
            ? 'The address is kept on this device only. '
            : 'Linking needs an OraSec account with organisation-wide access. Each linked device can be signed out from the web at any time. '}
          <button type="button" className="underline" onClick={() => void openExternalUrl(PRIVACY_POLICY_URL)}>
            Privacy
          </button>
        </p>
      </Block>
    </Page>
  )
}

