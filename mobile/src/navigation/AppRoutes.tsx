import { type ReactElement, Suspense, lazy } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'

import { GuestOnly, NotFound, RequireAuth, Splash } from '@/navigation/guards'
import LinkScreen from '@/screens/LinkScreen'
import OverviewScreen from '@/screens/OverviewScreen'

const VulnsScreen = lazy(() => import('@/screens/VulnsScreen'))
const FindingScreen = lazy(() => import('@/screens/FindingScreen'))
const AssetsScreen = lazy(() => import('@/screens/AssetsScreen'))
const AssetScreen = lazy(() => import('@/screens/AssetScreen'))
const AttacksScreen = lazy(() => import('@/screens/AttacksScreen'))
const GovernanceScreen = lazy(() => import('@/screens/GovernanceScreen'))
const RiskScreen = lazy(() => import('@/screens/RiskScreen'))
const CodeScreen = lazy(() => import('@/screens/CodeScreen'))
const ConnectorsScreen = lazy(() => import('@/screens/ConnectorsScreen'))
const MyWorkScreen = lazy(() => import('@/screens/MyWorkScreen'))
const MoreScreen = lazy(() => import('@/screens/MoreScreen'))
const AppearanceScreen = lazy(() => import('@/screens/settings/AppearanceScreen'))
const AppLockSettingsScreen = lazy(() => import('@/screens/native/AppLockSettingsScreen'))
const NotificationsScreen = lazy(() => import('@/screens/settings/NotificationsScreen'))

const auth = (el: ReactElement) => <RequireAuth>{el}</RequireAuth>

export function AppRoutes() {
  return (
    <Suspense fallback={<Splash />}>
      <Routes>
        <Route path="/link" element={<GuestOnly><LinkScreen /></GuestOnly>} />
        <Route path="/login" element={<Navigate to="/link" replace />} />

        <Route path="/" element={auth(<OverviewScreen />)} />
        <Route path="/vulns" element={auth(<VulnsScreen />)} />
        <Route path="/vulns/:id" element={auth(<FindingScreen />)} />
        <Route path="/assets" element={auth(<AssetsScreen />)} />
        <Route path="/assets/*" element={auth(<AssetScreen />)} />
        <Route path="/attacks" element={auth(<AttacksScreen />)} />
        <Route path="/governance" element={auth(<GovernanceScreen />)} />
        <Route path="/risks/:id" element={auth(<RiskScreen />)} />
        <Route path="/code" element={auth(<CodeScreen />)} />
        <Route path="/connectors" element={auth(<ConnectorsScreen />)} />
        <Route path="/my-work" element={auth(<MyWorkScreen />)} />
        <Route path="/more" element={auth(<MoreScreen />)} />
        <Route path="/settings/appearance" element={auth(<AppearanceScreen />)} />
        <Route path="/settings/app-lock" element={auth(<AppLockSettingsScreen />)} />
        <Route path="/settings/notifications" element={auth(<NotificationsScreen />)} />
        <Route path="*" element={<NotFound />} />
      </Routes>
    </Suspense>
  )
}
