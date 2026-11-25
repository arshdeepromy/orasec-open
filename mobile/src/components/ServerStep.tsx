import { type FormEvent, useState } from 'react'

import { SOURCE_URL } from '@/config/brand'
import { SERVER_PRESETS, addressProblem, checkServer, normalizeServerUrl, setServerUrl } from '@/config/serverConfig'
import { openExternalUrl } from '@/native/browser'

/**
 * First step on the link screen: which OraSec server does this device belong to?
 *
 * OraSec is self-hosted, so the app asks for the server's address, checks that an OraSec server answers there and
 * remembers it. Nothing else is sent: the check is a public "are you OraSec?" question with no sign-in.
 */
export default function ServerStep({ initial = '', onDone, onCancel }: { initial?: string; onDone: () => void; onCancel?: () => void }) {
  const [address, setAddress] = useState(initial)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const use = async (input: string) => {
    if (busy) return
    setError(null)
    if (!normalizeServerUrl(input)) {
      setError(addressProblem(input))
      return
    }
    setBusy(true)
    try {
      const result = await checkServer(input)
      if (!result.ok) {
        setError(result.message)
        return
      }
      await setServerUrl(result.url)
      onDone()
    } finally {
      setBusy(false)
    }
  }

  const submit = (e: FormEvent) => {
    e.preventDefault()
    void use(address)
  }

  return (
    <div data-testid="server-step">
      <h2 className="text-lg font-semibold text-[var(--text)]">Your OraSec server</h2>
      <p className="mb-4 mt-1 text-sm leading-relaxed text-[var(--muted)]">
        Enter the address of the OraSec server your organisation runs. The app only talks to that server.
      </p>

      {error ? (
        <div role="alert" className="mb-4 rounded-lg bg-[var(--danger-soft)] px-4 py-3 text-sm text-[var(--danger)]" data-testid="server-error">
          {error}
        </div>
      ) : null}

      <form onSubmit={submit} noValidate>
        <label htmlFor="server-address" className="mb-1.5 block text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
          Server address
        </label>
        <input
          id="server-address"
          data-testid="server-address"
          className="input"
          value={address}
          onChange={(e) => setAddress(e.target.value)}
          placeholder="orasec.example.com"
          autoCapitalize="none"
          autoComplete="url"
          autoCorrect="off"
          spellCheck={false}
          inputMode="url"
          enterKeyHint="go"
        />
        <button type="submit" className="btn btn-primary mt-5" disabled={busy || !address.trim()} data-testid="server-submit">
          {busy ? 'Checking…' : 'Continue'}
        </button>
      </form>

      {onCancel ? (
        <button type="button" className="btn btn-ghost mt-3" onClick={onCancel} disabled={busy} data-testid="server-cancel">
          Keep the current server
        </button>
      ) : null}

      {SERVER_PRESETS.length ? (
        <div className="mt-4 flex flex-col gap-2" data-testid="server-presets">
          {SERVER_PRESETS.map((preset) => (
            <button
              key={preset.url}
              type="button"
              disabled={busy}
              onClick={() => void use(preset.url)}
              className="rounded-xl border border-[var(--input-border)] px-3 py-2.5 text-left"
            >
              <span className="block text-sm font-medium text-[var(--text)]">{preset.label}</span>
              <span className="block text-xs text-[var(--muted)]">
                {preset.url.replace(/^https?:\/\//, '')}
                {preset.hint ? ` · ${preset.hint}` : ''}
              </span>
            </button>
          ))}
        </div>
      ) : null}

      {SOURCE_URL ? (
        <p className="mt-5 text-xs leading-relaxed text-[var(--muted)]">
          OraSec is free and open source. No server yet?{' '}
          <button type="button" className="underline" onClick={() => void openExternalUrl(SOURCE_URL)} data-testid="host-your-own">
            Host your own
          </button>
          .
        </p>
      ) : null}
    </div>
  )
}
