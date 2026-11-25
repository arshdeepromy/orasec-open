import { Capacitor } from '@capacitor/core'
import { useState } from 'react'

import { PinSetup } from '@/components/security/AppLockGate'
import { ChangePin, ConfirmPin } from '@/components/security/ChangePin'
import { Icon, I, Screen, SectionLabel } from '@/components/ui/ds'
import { useAuth } from '@/contexts/AuthContext'
import { useBiometric } from '@/contexts/BiometricContext'
import { useHaptics } from '@/hooks/useHaptics'
import { DEFAULT_RELOCK_MS, RELOCK_OPTIONS, saveAppLockSettings, updateAppLockSettings, useAppLockSettings } from '@/security/appLock'
import { clearPin, hasPin, setSignInNotice } from '@/security/appPin'

import '@/components/native/native.css'

type Overlay = 'none' | 'enable' | 'disable' | 'change'

/**
 * Settings → App lock: turn the PIN / Face ID / fingerprint lock on or off,
 * change the PIN, and choose how soon the app locks again in the background.
 * Turning the lock off asks for the PIN first.
 */
export default function AppLockSettingsScreen() {
  const { user, signOut } = useAuth()
  const biometric = useBiometric()
  const haptics = useHaptics()
  const userId = user ? String(user.id) : null
  const settings = useAppLockSettings(userId)
  const [overlay, setOverlay] = useState<Overlay>('none')
  const [, bump] = useState(0)
  const native = Capacitor.isNativePlatform()

  const lockOn = settings?.enabled === true && hasPin(userId)
  const timeoutMs = settings?.timeoutMs ?? DEFAULT_RELOCK_MS

  const lockedOut = () => {
    setOverlay('none')
    setSignInNotice('Too many wrong PIN attempts. This phone was signed out: create a new link code in OraSec to link it again.')
    void signOut()
  }

  const turnOff = () => {
    if (!userId) return
    clearPin()
    biometric.setEnabled(false)
    saveAppLockSettings({ userId, enabled: false, timeoutMs })
    setOverlay('none')
    void haptics.medium()
    bump((n) => n + 1)
  }

  if (!userId) return null

  if (overlay === 'enable') {
    return (
      <PinSetup
        userId={userId}
        required
        offerBiometric={biometric.isAvailable && !biometric.isEnabled}
        biometricLabel={biometric.label}
        verifyBiometric={biometric.verify}
        enableBiometric={() => biometric.setEnabled(true)}
        onDone={() => {
          updateAppLockSettings(userId, { enabled: true })
          setOverlay('none')
          void haptics.medium()
        }}
        onSkip={() => setOverlay('none')}
      />
    )
  }
  if (overlay === 'disable') {
    return (
      <ConfirmPin
        userId={userId}
        title="Enter your PIN"
        subtitle="Confirm it’s you to turn off the app lock."
        onConfirmed={turnOff}
        onCancel={() => setOverlay('none')}
        onLockedOut={lockedOut}
      />
    )
  }
  if (overlay === 'change') {
    return (
      <ChangePin
        userId={userId}
        onDone={() => {
          setOverlay('none')
          void haptics.medium()
        }}
        onCancel={() => setOverlay('none')}
        onLockedOut={lockedOut}
      />
    )
  }

  return (
    <Screen title="App lock" back="/more">
      {!native && (
        <div className="native-callout info" role="note">
          <Icon d={I.lock} size={18} />
          <span>The app lock works in the installed OraSec app. In this preview the switches are shown for review only.</span>
        </div>
      )}

      <div className="native-settings">
        <section>
          <SectionLabel>Lock</SectionLabel>
          <div className="list">
            <button
              type="button"
              className="native-toggle-row"
              role="switch"
              aria-checked={lockOn}
              aria-disabled={!native || undefined}
              disabled={!native}
              onClick={() => setOverlay(lockOn ? 'disable' : 'enable')}
              data-testid="app-lock-toggle"
            >
              <span className="body">
                <span className="t">App lock</span>
                <span className="s">Open OraSec with a 6-digit PIN</span>
              </span>
              <span className={`native-switch${lockOn ? ' on' : ''}`} aria-hidden="true" />
            </button>
            {lockOn && biometric.isAvailable && (
              <button
                type="button"
                className="native-toggle-row"
                role="switch"
                aria-checked={biometric.isEnabled}
                onClick={async () => {
                  if (biometric.isEnabled) {
                    biometric.setEnabled(false)
                  } else if (await biometric.verify()) {
                    biometric.setEnabled(true)
                  }
                  void haptics.selection()
                }}
                data-testid="app-lock-biometric"
              >
                <span className="body">
                  <span className="t">Unlock with {biometric.label}</span>
                  <span className="s">Your PIN always works too</span>
                </span>
                <span className={`native-switch${biometric.isEnabled ? ' on' : ''}`} aria-hidden="true" />
              </button>
            )}
            {lockOn && (
              <button type="button" className="li" onClick={() => setOverlay('change')} data-testid="app-lock-change-pin">
                <span className="body">
                  <span className="t">Change PIN</span>
                </span>
                <span className="chev">
                  <Icon d={I.chevR} size={19} />
                </span>
              </button>
            )}
          </div>
        </section>

        <section>
          <SectionLabel>Lock again after leaving the app</SectionLabel>
          <div className="list" role="radiogroup" aria-label="Lock again after leaving the app">
            {RELOCK_OPTIONS.map((option) => {
              const selected = option.ms === timeoutMs
              return (
                <button
                  key={option.ms}
                  type="button"
                  role="radio"
                  aria-checked={selected}
                  className="native-option"
                  disabled={!lockOn}
                  onClick={() => {
                    updateAppLockSettings(userId, { timeoutMs: option.ms })
                    void haptics.selection()
                  }}
                >
                  {option.label}
                  {selected && (
                    <span className="check">
                      <Icon d={I.check} size={18} stroke={2.4} />
                    </span>
                  )}
                </button>
              )
            })}
          </div>
          <p className="native-note mt-2">
            The app also locks every time it starts. Five wrong PINs sign you out; you then link the phone again with a new code from OraSec.
          </p>
        </section>
      </div>
    </Screen>
  )
}

