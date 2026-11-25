import { useLocation, useNavigate } from 'react-router-dom'

import { BrandMark } from '@/components/BrandMark'
import OraOrb from '@/components/ora/OraOrb'
import { openOra } from '@/components/ora/OraHost'
import { ATTACK_SOURCES, anyPluginOn, pluginOn, usePlugins, type PluginMap } from '@/plugins/pluginState'
import { ICONS } from '@/components/sec'
import { I, Icon } from '@/components/ui/ds'
import { useAuth } from '@/contexts/AuthContext'
import { initials } from '@/utils/format'

/**
 * Tablet navigation (replaces the phone's bottom tab bar from 600 CSS px).
 * - `rail`: icons with short labels (7"/10" tablets, iPad portrait).
 * - `expanded`: full sidebar with sections, brand and the signed-in person (iPad / tablet landscape).
 * Every section is one tap away, including the ones that sit under "More" on a phone.
 */
type Item = { id: string; label: string; short: string; path: string; icon: string; match: (p: string) => boolean }

const starts = (...prefixes: string[]) => (p: string) => prefixes.some((x) => p === x || p.startsWith(`${x}/`))

const PRIMARY: Item[] = [
  { id: 'home', label: 'Overview', short: 'Overview', path: '/', icon: ICONS.shield, match: (p) => p === '/' },
  { id: 'vulns', label: 'Vulnerabilities', short: 'Vulns', path: '/vulns', icon: ICONS.bug, match: starts('/vulns') },
  { id: 'attacks', label: 'Attacks', short: 'Attacks', path: '/attacks', icon: ICONS.globe, match: starts('/attacks') },
  { id: 'governance', label: 'Risk & ISO 27001', short: 'Risk', path: '/governance', icon: ICONS.scale, match: starts('/governance', '/risks') },
]

const WORK: Item[] = [
  { id: 'my-work', label: 'My work', short: 'My work', path: '/my-work', icon: ICONS.stopwatch, match: starts('/my-work') },
  { id: 'assets', label: 'Assets', short: 'Assets', path: '/assets', icon: ICONS.server, match: starts('/assets') },
  { id: 'code', label: 'Code', short: 'Code', path: '/code', icon: ICONS.code, match: starts('/code') },
  { id: 'connectors', label: 'Data sources', short: 'Sources', path: '/connectors', icon: ICONS.plug, match: starts('/connectors') },
]

/** The source plugins that feed the Attacks screen (see plugins/pluginState.ts). */
const shown = (it: Item, plugins: PluginMap | null) => it.id !== 'attacks' || anyPluginOn(ATTACK_SOURCES, plugins)

const SETTINGS: Item = { id: 'more', label: 'Settings', short: 'Settings', path: '/more', icon: I.cog, match: starts('/more', '/settings') }

export function SideNav({ expanded }: { expanded: boolean }) {
  const navigate = useNavigate()
  const { pathname } = useLocation()
  const { user } = useAuth()
  const path = pathname.replace(/\/+$/, '') || '/'
  const plugins = usePlugins()

  const entry = (it: Item) => {
    const on = it.match(path)
    return (
      <button
        key={it.id}
        type="button"
        className={`snav-item${on ? ' on' : ''}`}
        aria-current={on ? 'page' : undefined}
        aria-label={it.label}
        title={expanded ? undefined : it.label}
        onClick={() => navigate(it.path)}
        data-testid={`snav-${it.id}`}
      >
        <span className="snav-ico">
          <Icon d={it.icon} size={21} stroke={1.7} />
        </span>
        <span className="snav-l" aria-hidden="true">
          {expanded ? it.label : it.short}
        </span>
      </button>
    )
  }

  return (
    <nav className={`snav${expanded ? ' expanded' : ''}`} aria-label="Main" data-testid="sidenav">
      {expanded ? (
        <div className="snav-brand">
          <BrandMark size={34} />
          <div>
            <div className="snav-brand-t">OraSec</div>
            <div className="snav-brand-s">Security operations</div>
          </div>
        </div>
      ) : (
        <div className="snav-brand compact">
          <BrandMark size={36} />
        </div>
      )}

      <div className="snav-scroll">
        <div className="snav-group">{PRIMARY.filter((it) => shown(it, plugins)).map(entry)}</div>
        {expanded ? <div className="snav-h">Workspace</div> : <div className="snav-sep" aria-hidden="true" />}
        <div className="snav-group">{WORK.map(entry)}</div>
      </div>

      <div className="snav-foot">
        {pluginOn('ora', plugins) ? (
          <button type="button" className="snav-item" onClick={openOra} aria-label="Ask Ora" title={expanded ? undefined : 'Ask Ora'} data-testid="snav-ora">
            <span className="snav-ico">
              <OraOrb size={24} decorative />
            </span>
            <span className="snav-l" aria-hidden="true">
              {expanded ? 'Ask Ora' : 'Ora'}
            </span>
          </button>
        ) : null}
        {expanded ? (
          <button type="button" className={`snav-user${SETTINGS.match(path) ? ' on' : ''}`} onClick={() => navigate('/more')} aria-label="Settings and profile" data-testid="snav-more">
            <span className="snav-av">{initials(user?.name, user?.email)}</span>
            <span className="snav-user-t">
              <span className="snav-user-n">{user?.name ?? 'Signed in'}</span>
              <span className="snav-user-s">Settings</span>
            </span>
            <Icon d={I.cog} size={18} />
          </button>
        ) : (
          entry(SETTINGS)
        )}
      </div>
    </nav>
  )
}

