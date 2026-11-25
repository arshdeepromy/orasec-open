import { ICONS } from '@/components/sec'
import { I } from '@/components/ui/ds'
import { ATTACK_SOURCES, anyPluginOn, type PluginMap } from '@/plugins/pluginState'

/** The floating bottom bar: the four main OraSec views plus More (same pattern as the publisher's other apps). */
export type TabId = 'home' | 'vulns' | 'attacks' | 'governance' | 'more'

export type TabConfig = {
  id: TabId
  label: string
  path: string
  iconPath: string
}

export const TABS: TabConfig[] = [
  { id: 'home', label: 'Overview', path: '/', iconPath: ICONS.shield },
  { id: 'vulns', label: 'Vulns', path: '/vulns', iconPath: ICONS.bug },
  { id: 'attacks', label: 'Attacks', path: '/attacks', iconPath: ICONS.globe },
  { id: 'governance', label: 'Risk', path: '/governance', iconPath: ICONS.scale },
  { id: 'more', label: 'More', path: '/more', iconPath: I.dots },
]

/** The tabs to show: Attacks only when a source that feeds it works on the server. */
export function visibleTabs(plugins: PluginMap | null): TabConfig[] {
  return TABS.filter((tab) => tab.id !== 'attacks' || anyPluginOn(ATTACK_SOURCES, plugins))
}

/** Screens that keep the bar visible (the five sections' own pages). */
export function isTopLevelPath(path: string): boolean {
  const clean = path.replace(/\/+$/, '') || '/'
  return clean === '/' || TABS.some((t) => t.path === clean)
}

/** Which tab owns a path (detail screens highlight their section). */
export function activeTabId(path: string): TabId | null {
  const clean = path.replace(/\/+$/, '') || '/'
  if (clean === '/') return 'home'
  if (clean.startsWith('/risks')) return 'governance'
  if (['/assets', '/code', '/connectors', '/my-work', '/settings'].some((p) => clean.startsWith(p))) return 'more'
  for (const tab of TABS) {
    if (tab.path !== '/' && (clean === tab.path || clean.startsWith(`${tab.path}/`))) return tab.id
  }
  return null
}
