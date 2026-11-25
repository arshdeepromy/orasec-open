import { registerPlugin } from '@capacitor/core'
import { type ReactNode, useEffect } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'

import OraHost from '@/components/ora/OraHost'
import { SideNav } from '@/components/shell/SideNav'
import { Icon } from '@/components/ui/ds'
import { useAuth } from '@/contexts/AuthContext'
import { useOptionalAppearance } from '@/contexts/AppearanceContext'
import { useLayout } from '@/hooks/useLayout'
import { useNetworkStatus } from '@/hooks/useNetworkStatus'
import { activeTabId, isTopLevelPath, visibleTabs } from '@/navigation/tabs'
import { pluginOn, usePlugins } from '@/plugins/pluginState'

/** Android status-bar appearance shim (OraStatusBarPlugin.java, as in the invoicing app). */
const OraStatusBar = registerPlugin<{ setLightSurface(options: { light: boolean }): Promise<void> }>('OraStatusBar')

/** Routes rendered without the app chrome (signed-out flows, public signing). */
const BARE_PREFIXES = ['/link']

/**
 * App shell — the same structure as the invoicing app's KonstaShell:
 * offline banner, a capped scroll column, and the floating pill tab bar on
 * top-level screens. Detail and form screens bring their own action bars.
 * Tablets (>= 600 CSS px) get a navigation rail / sidebar instead of the tab
 * bar, and the screens lay themselves out in columns (see tablet.css).
 */
export function AppShell({ children }: { children: ReactNode }) {
  const location = useLocation()
  const { status } = useAuth()
  const { isOnline } = useNetworkStatus()
  const { size } = useLayout()
  const rail = size !== 'phone'
  const oraOn = pluginOn('ora', usePlugins())
  const path = location.pathname
  const bare = status !== 'signedIn' || BARE_PREFIXES.some((p) => path === p.replace(/\/$/, '') || path.startsWith(p))

  // One scroll container serves every screen, so a new screen must start at
  // the top (it used to open wherever the previous screen was scrolled to).
  useEffect(() => {
    document.getElementById('main-scroll')?.scrollTo({ top: 0 })
  }, [path])

  // The link screen opens with the dark brand header: paint the status-bar
  // strip the same colour so there is no light band above it (as in the invoicing app).
  const brandTop = status !== 'signedIn' && path === '/link'
  // The link screen always uses the brand look (OraSec console dark), like the
  // icon and splash; every other screen keeps the person's own appearance.
  const brandSurface = path === '/link'
  useEffect(() => {
    document.body.classList.toggle('ora-brand-top', brandTop)
    return () => document.body.classList.remove('ora-brand-top')
  }, [brandTop])

  const isDark = useOptionalAppearance()?.isDark ?? false
  const darkSurface = bare || isDark

  // Keep the status-bar text legible over the edge-to-edge canvas (see
  // the invoicing app's KonstaShell for the full story; Style names the BACKGROUND).
  useEffect(() => {
    let cancelled = false
    const apply = async () => {
      try {
        const { Capacitor } = await import('@capacitor/core')
        if (!Capacitor.isNativePlatform() || cancelled) return
        if (Capacitor.getPlatform() === 'android') {
          await OraStatusBar.setLightSurface({ light: !darkSurface })
          return
        }
        const { StatusBar, Style } = await import('@capacitor/status-bar')
        await StatusBar.setStyle({ style: darkSurface ? Style.Dark : Style.Light })
      } catch {
        // Plugin unavailable — nothing to do.
      }
    }
    void apply()
    const retry = window.setTimeout(() => void apply(), 1200)
    return () => {
      cancelled = true
      window.clearTimeout(retry)
    }
  }, [darkSurface])

  if (bare) {
    return (
      <div className={`auth-shell${brandSurface ? ' brand-surface' : ''} flex min-h-[100dvh] w-full flex-col bg-[var(--ink)] min-[700px]:items-center min-[700px]:justify-center min-[700px]:p-10`}>
        <div className="auth-card relative mx-auto flex w-full max-w-[var(--auth-max)] flex-1 flex-col bg-[var(--card-solid)] min-[700px]:max-w-[var(--auth-card)] min-[700px]:flex-none min-[700px]:overflow-hidden min-[700px]:rounded-[28px] min-[700px]:shadow-[var(--shadow-pop)]">
          {children}
        </div>
      </div>
    )
  }

  return (
    <div className={`flex h-[100dvh] w-full overflow-hidden${rail ? ' has-rail' : ''}`}>
      {rail ? <SideNav expanded={size === 'wide'} /> : null}
      <div className="flex min-w-0 flex-1 flex-col">
        {!isOnline && (
          <div className="bg-red-600 px-4 py-1.5 text-center text-xs font-medium text-white" role="alert" data-testid="offline-banner">
            You are offline
          </div>
        )}
        <main
          id="main-scroll"
          className={`relative mx-auto flex w-full min-h-0 flex-1 flex-col overflow-y-auto ${rail ? 'tablet-main' : 'max-w-[var(--content-max)]'}`}
        >
          {children}
        </main>
        {!rail && isTopLevelPath(path) && <TabBar />}
        {oraOn ? <OraHost bubble={!rail} /> : null}
      </div>
    </div>
  )
}

function TabBar() {
  const navigate = useNavigate()
  const location = useLocation()
  const active = activeTabId(location.pathname)
  const plugins = usePlugins()

  return (
    <nav data-testid="tabbar" aria-label="Main" className="konsta-tabbar-fixed ora-tabbar px-3">
      <div
        className="ora-tabbar-inner mx-auto flex h-[64px] max-w-[560px] items-stretch gap-1 rounded-[26px] p-1.5"
        role="tablist"
      >
        {visibleTabs(plugins).map((tab) => {
          const isActive = tab.id === active
          return (
            <button
              key={tab.id}
              type="button"
              role="tab"
              aria-selected={isActive}
              aria-current={isActive ? 'page' : undefined}
              aria-label={tab.label}
              onClick={() => navigate(tab.path)}
              data-testid={`tab-${tab.id}`}
              className="ora-tab flex min-h-[44px] min-w-[44px] flex-1 select-none flex-col items-center justify-center gap-0.5 rounded-[20px] transition-colors duration-150 active:scale-[0.97]"
            >
              <Icon d={tab.iconPath} size={22} stroke={1.7} />
              <span className={`max-w-full truncate text-[11px] leading-tight ${isActive ? 'font-semibold' : 'font-medium'}`} aria-hidden="true">
                {tab.label}
              </span>
            </button>
          )
        })}
      </div>
    </nav>
  )
}

