import { useAuth } from '@/contexts/AuthContext'
import { usePrivacyScreen } from '@/native/privacyScreen'
import { useAppLockSettings } from '@/security/appLock'

/**
 * Keeps screenshot / app-switcher protection in step with the screen
 * (native/privacyScreen.ts). Mount once (App.tsx).
 */
export function PrivacyGuard() {
  const { user } = useAuth()
  const lockEnabled = useAppLockSettings(user ? String(user.id) : null)?.enabled === true
  usePrivacyScreen(lockEnabled)
  return null
}
