import { Capacitor } from '@capacitor/core'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'

import OraOrb from '@/components/ora/OraOrb'
import { openOra } from '@/components/ora/OraHost'
import { ICONS } from '@/components/sec'
import { I, Icon, ListRow, Screen, SectionLabel } from '@/components/ui/ds'
import { Sheet } from '@/components/ui/Sheet'
import { PRIVACY_POLICY_URL, PUBLISHER, SOURCE_URL } from '@/config/brand'
import { getDisplayServerUrl, webAppUrl } from '@/config/serverConfig'
import { useAppearance } from '@/contexts/AppearanceContext'
import { useAuth } from '@/contexts/AuthContext'
import { isDemoSession } from '@/demo/session'
import { useLayout } from '@/hooks/useLayout'
import { openExternalUrl } from '@/native/browser'
import { isPushOptedIn } from '@/notifications/pushController'
import { pluginOn, usePlugins } from '@/plugins/pluginState'
import { useAppLockSettings } from '@/security/appLock'
import { APPEARANCE_LABELS } from '@/theme/appearance'
import { APP_VERSION } from '@/utils/appVersion'
import { initials } from '@/utils/format'

/** Everything that is not one of the four main tabs, plus app settings and sign-out. */
export default function MoreScreen() {
  const navigate = useNavigate()
  const { user, device, signOut } = useAuth()
  const { preference } = useAppearance()
  const lock = useAppLockSettings(user ? String(user.id) : null)
  const [confirm, setConfirm] = useState(false)
  const [busy, setBusy] = useState(false)
  const { isTablet } = useLayout()
  const demo = isDemoSession()
  const plugins = usePlugins()

  return (
    <Screen title={isTablet ? 'Settings' : 'More'} large>
      <div className="t-2col">
      <div className="col">
      <section className="card card-pad" style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
        <div className="av tint" style={{ width: 46, height: 46, borderRadius: 13, display: 'grid', placeItems: 'center', fontWeight: 700, background: 'var(--accent-soft)', color: 'var(--accent-fg)' }}>
          {initials(user?.name, user?.email)}
        </div>
        <div style={{ minWidth: 0 }}>
          <div style={{ fontWeight: 700 }}>{user?.name}</div>
          <div className="hero-s" style={{ marginTop: 0 }}>
            {user?.email || user?.username}
          </div>
          <div className="hero-s" style={{ marginTop: 2 }}>
            {demo ? 'Demo mode · sample data only' : `${device?.name} · linked to ${getDisplayServerUrl()}`}
          </div>
        </div>
      </section>

      <SectionLabel>Security</SectionLabel>
      <div className="list">
        {pluginOn('ora', plugins) ? (
          <ListRow av={<OraOrb size={30} decorative />} title="Ask Ora" sub="Prioritise, evaluate risk, find your way" onClick={openOra} />
        ) : null}
        <ListRow av={<Icon d={ICONS.stopwatch} />} title="My work" sub="Assigned to me and overdue" onClick={() => navigate('/my-work')} />
        <ListRow av={<Icon d={ICONS.server} />} title="Assets" sub="Hosts, containers, code, cloud" onClick={() => navigate('/assets')} />
        <ListRow av={<Icon d={ICONS.code} />} title="Code" sub="Vulnerabilities by product" onClick={() => navigate('/code')} />
        <ListRow av={<Icon d={ICONS.plug} />} title="Data sources" sub="Connectors, feeds and plugins" onClick={() => navigate('/connectors')} />
        {demo ? null : (
          <ListRow av={<Icon d={ICONS.globe} />} title="Open OraSec on the web" sub="The full console in your browser" onClick={() => void openExternalUrl(webAppUrl('/dashboard'))} />
        )}
      </div>
      </div>
      <div className="col">

      <SectionLabel>App</SectionLabel>
      <div className="list">
        {Capacitor.isNativePlatform() ? (
          <ListRow av={<Icon d={I.lock} />} title="App lock" sub={lock?.enabled ? 'On' : 'Off'} onClick={() => navigate('/settings/app-lock')} />
        ) : null}
        {pluginOn('push', plugins) ? (
          <ListRow av={<Icon d={I.bell} />} title="Notifications" sub={isPushOptedIn() ? 'On' : 'Off'} onClick={() => navigate('/settings/notifications')} />
        ) : null}
        <ListRow av={<Icon d={ICONS.moon} />} title="Appearance" sub={APPEARANCE_LABELS[preference]} onClick={() => navigate('/settings/appearance')} />
        <ListRow av={<Icon d={ICONS.info} />} title="Privacy" sub="What the app stores and sends" onClick={() => void openExternalUrl(PRIVACY_POLICY_URL)} />
        {SOURCE_URL ? (
          <ListRow av={<Icon d={ICONS.code} />} title="Source code" sub="OraSec is free and open source" onClick={() => void openExternalUrl(SOURCE_URL)} />
        ) : null}
        <ListRow
          av={<Icon d={ICONS.logout} />}
          title={demo ? 'Leave the demo' : `Sign out of this ${isTablet ? 'device' : 'phone'}`}
          sub={demo ? 'Back to the link screen' : 'Unlinks it from OraSec'}
          onClick={() => setConfirm(true)}
        />
      </div>

      <p className="updated" style={{ marginTop: 18 }}>
        OraSec {APP_VERSION} · {PUBLISHER}
      </p>
      </div>
      </div>

      <Sheet
        open={confirm}
        title={demo ? 'Leave the demo?' : 'Sign out of this phone?'}
        onClose={() => setConfirm(false)}
        footer={
          <button
            className="btn btn-danger"
            disabled={busy}
            data-testid="confirm-signout"
            onClick={async () => {
              setBusy(true)
              await signOut()
              setBusy(false)
              setConfirm(false)
              navigate('/link', { replace: true })
            }}
          >
            {busy ? 'Signing out…' : demo ? 'Leave the demo' : 'Sign out'}
          </button>
        }
      >
        <p className="prose muted">
          {demo ? 'The sample data and any changes you made are cleared. You can start the demo again from the link screen.' : null}
          {demo ? null : <>The phone is unlinked from OraSec and its sign-in is revoked. To use the app again, create a new link code in
          OraSec (Profile menu → Mobile app).</>}
        </p>
      </Sheet>
    </Screen>
  )
}

