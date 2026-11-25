import { Capacitor } from '@capacitor/core'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'

import { hydrateDeviceToken } from '@/api/session'
import { hydrateServerUrl } from '@/config/serverConfig'
import { capacitorInit } from '@/native/capacitor-init'
import { restoreAndTrackInsets } from '@/native/insetsMemory'
import { hydrateLockState } from '@/security/lockStore'
import { applyAppearance, installAppearanceCss, readCachedPreference, resolveAppearance } from '@/theme/appearance'

import App from './App'
import './fonts'
import { systemPrefersDark } from '@/theme/systemTheme'
import './index.css'
import './tablet.css'

// Paint the last-used appearance before anything renders (no flash).
installAppearanceCss()
applyAppearance(
  resolveAppearance(readCachedPreference(), systemPrefersDark()),
)

// Android: put back the system-bar insets a reload wiped (see insetsMemory.ts).
if (Capacitor.getPlatform() === 'android') restoreAndTrackInsets()

// Load the selected server, the device token and the app-lock state (from the Keychain / Keystore vault) before
// anything issues a request or paints, then render.
Promise.all([capacitorInit(), hydrateServerUrl(), hydrateDeviceToken(), hydrateLockState()]).then(() => {
  const root = document.getElementById('root')
  if (!root) return
  createRoot(root).render(
    <StrictMode>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </StrictMode>,
  )
})
