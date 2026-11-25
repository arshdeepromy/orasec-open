import { App as KonstaApp } from 'konsta/react'

import { AndroidBackHandler } from '@/components/AndroidBackHandler'
import { PrivacyGuard } from '@/components/native/PrivacyGuard'
import { AppLockGate } from '@/components/security/AppLockGate'
import { AppShell } from '@/components/shell/AppShell'
import { AppearanceProvider } from '@/contexts/AppearanceContext'
import { AuthProvider } from '@/contexts/AuthContext'
import { BiometricProvider } from '@/contexts/BiometricContext'
import { AppRoutes } from '@/navigation/AppRoutes'
import PushHost from '@/notifications/PushHost'

/**
 * Konsta theme is pinned to 'ios' on every platform — the design system (index.css, shared with the OraFlows and
 * OraSec apps) is authored against it.
 */
export default function App() {
  return (
    <KonstaApp theme="ios" safeAreas dark>
      <AuthProvider>
        <AppearanceProvider>
          {/* App lock (PIN / Face ID / fingerprint) over the whole app, and the privacy screen in the app switcher.
              No-ops in the browser preview. */}
          <BiometricProvider>
            <AppLockGate>
              <AppShell>
                <AndroidBackHandler />
                <PushHost />
                <AppRoutes />
              </AppShell>
            </AppLockGate>
            <PrivacyGuard />
          </BiometricProvider>
        </AppearanceProvider>
      </AuthProvider>
    </KonstaApp>
  )
}
