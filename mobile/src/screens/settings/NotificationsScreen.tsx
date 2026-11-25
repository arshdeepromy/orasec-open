import { useEffect, useState } from 'react'

import { orasec, PUSH_KINDS, type PushKind, type PushState } from '@/api/orasec'
import { Icon, I, Screen, SectionLabel } from '@/components/ui/ds'
import { isDemoSession } from '@/demo/session'
import { useHaptics } from '@/hooks/useHaptics'
import { pushSupported } from '@/native/push'
import { isPushOptedIn, turnOffPush, turnOnPush } from '@/notifications/pushController'

import '@/components/native/native.css'

const KINDS: Record<PushKind, { title: string; sub: string }> = {
  critical: { title: 'Critical findings', sub: 'A new critical or known-exploited vulnerability' },
  alerts: { title: 'Security alerts', sub: 'A high-severity alert from the monitoring tools' },
  approvals: { title: 'Approvals waiting for me', sub: 'A change or exception needs my decision (08:00 to 20:00)' },
  overdue: { title: 'Overdue findings', sub: 'A finding passed its fix-by date (08:00 to 20:00)' },
}
const ORDER: PushKind[] = ['critical', 'alerts', 'approvals', 'overdue']

/**
 * Settings → Notifications: switch notifications on for this phone, choose which of the four kinds to get, and
 * send a test. The phone asks for permission only when the person switches them on here.
 */
export default function NotificationsScreen() {
  const haptics = useHaptics()
  const native = pushSupported()
  const demo = isDemoSession()
  const [state, setState] = useState<PushState | null>(null)
  const [on, setOn] = useState(isPushOptedIn())
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState<{ tone: 'info' | 'warn'; text: string } | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    orasec
      .pushState(controller.signal)
      .then((s) => {
        setState(s)
        if (!s.registered) setOn(false)
      })
      .catch(() => {
        if (!controller.signal.aborted) setState({ available: false, registered: false, settings: Object.fromEntries(PUSH_KINDS.map((k) => [k, true])) as PushState['settings'] })
      })
    return () => controller.abort()
  }, [])

  const canUse = native && !demo && state?.available === true
  const active = on && canUse

  const toggleMain = async () => {
    if (busy || !canUse) return
    setBusy(true)
    setNotice(null)
    if (on) {
      const next = await turnOffPush()
      if (next) setState(next)
      setOn(false)
    } else {
      const result = await turnOnPush()
      if (result.ok) {
        setState(result.state)
        setOn(true)
        void haptics.medium()
      } else {
        setNotice({ tone: 'warn', text: result.message })
      }
    }
    setBusy(false)
  }

  const toggleKind = async (kind: PushKind) => {
    if (!state || busy || !active) return
    const value = !state.settings[kind]
    setState({ ...state, settings: { ...state.settings, [kind]: value } })
    void haptics.selection()
    try {
      setState(await orasec.pushSaveSettings({ [kind]: value }))
    } catch {
      setState(state)
      setNotice({ tone: 'warn', text: 'Could not save that. Check the connection and try again.' })
    }
  }

  const sendTest = async () => {
    setBusy(true)
    setNotice(null)
    try {
      const result = await orasec.pushTest()
      setNotice(result.ok ? { tone: 'info', text: 'Test sent. It should show on this phone in a few seconds.' } : { tone: 'warn', text: result.detail })
    } catch (error) {
      setNotice({ tone: 'warn', text: error instanceof Error ? error.message : 'Could not send the test.' })
    }
    setBusy(false)
  }

  let blocked: string | null = null
  if (demo) blocked = 'This is the demo. Notifications need a phone that is linked to an OraSec account.'
  else if (!native) blocked = 'Notifications work in the installed OraSec app. In this preview the switches are shown for review only.'
  else if (state && !state.available) blocked = 'Your OraSec server does not send notifications yet. Ask your OraSec administrator.'

  return (
    <Screen title="Notifications" back="/more">
      {blocked && (
        <div className="native-callout info" role="note" data-testid="push-blocked">
          <Icon d={I.bell} size={18} />
          <span>{blocked}</span>
        </div>
      )}
      {notice && (
        <div className={`native-callout ${notice.tone}`} role="status" data-testid="push-notice">
          <Icon d={notice.tone === 'warn' ? I.alert : I.check} size={18} />
          <span>{notice.text}</span>
        </div>
      )}

      <div className="native-settings">
        <section>
          <SectionLabel>This phone</SectionLabel>
          <div className="list">
            <button
              type="button"
              className="native-toggle-row"
              role="switch"
              aria-checked={active}
              aria-disabled={!canUse || undefined}
              disabled={!canUse || busy}
              onClick={() => void toggleMain()}
              data-testid="push-toggle"
            >
              <span className="body">
                <span className="t">Notifications</span>
                <span className="s">Tell me on this phone when something needs attention</span>
              </span>
              <span className={`native-switch${active ? ' on' : ''}`} aria-hidden="true" />
            </button>
          </div>
          {active && (
            <button type="button" className="btn btn-ghost mt-3" disabled={busy} onClick={() => void sendTest()} data-testid="push-test">
              {busy ? 'Sending…' : 'Send a test notification'}
            </button>
          )}
        </section>

        <section>
          <SectionLabel>Tell me about</SectionLabel>
          <div className="list">
            {ORDER.map((kind) => {
              const checked = state?.settings[kind] ?? true
              return (
                <button
                  key={kind}
                  type="button"
                  className="native-toggle-row"
                  role="switch"
                  aria-checked={active && checked}
                  aria-disabled={!active || undefined}
                  disabled={!active}
                  onClick={() => void toggleKind(kind)}
                  data-testid={`push-kind-${kind}`}
                >
                  <span className="body">
                    <span className="t">{KINDS[kind].title}</span>
                    <span className="s">{KINDS[kind].sub}</span>
                  </span>
                  <span className={`native-switch${active && checked ? ' on' : ''}`} aria-hidden="true" />
                </button>
              )
            })}
          </div>
          {/* Right padding keeps the text clear of the round Ora button, which rests in this corner on most phones.
              Inline, because .native-note sets its own padding after the utility classes. */}
          <p className="native-note mt-2" style={{ paddingRight: '4rem' }}>
            A notification never shows the name of a finding, a device or a person. It only says what kind of thing is waiting and how
            many. The details are in the app, behind your app lock. Your choices here apply to all your phones.
          </p>
        </section>

      </div>
    </Screen>
  )
}
