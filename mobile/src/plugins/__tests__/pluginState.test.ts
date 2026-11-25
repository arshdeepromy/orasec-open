import { beforeEach, describe, expect, it } from 'vitest'

import { visibleTabs } from '@/navigation/tabs'
import { ATTACK_SOURCES, anyPluginOn, getPlugins, pluginOn, setPlugins } from '@/plugins/pluginState'
import { groupPlugins } from '@/screens/ConnectorsScreen'

describe('plugins', () => {
  beforeEach(() => setPlugins(null))

  it('everything is shown when the server sends no list (a server from before plugins)', () => {
    expect(getPlugins()).toBeNull()
    expect(pluginOn('ora')).toBe(true)
    expect(pluginOn('anything.at.all')).toBe(true)
    expect(visibleTabs(null).map((t) => t.id)).toEqual(['home', 'vulns', 'attacks', 'governance', 'more'])
  })

  it('a plugin is off only when the server says so', () => {
    setPlugins({ ora: false, push: true })
    expect(pluginOn('ora')).toBe(false)
    expect(pluginOn('push')).toBe(true)
    expect(pluginOn('not.in.the.list')).toBe(true)
  })

  it('ignores a list that is not a list of on/off values', () => {
    setPlugins({ ora: false })
    setPlugins(['ora'])
    expect(getPlugins()).toBeNull()
    setPlugins({ ora: 'no' })
    expect(getPlugins()).toBeNull()
  })

  it('keeps the list for the next start and forgets it when unlinked', () => {
    setPlugins({ ora: false })
    expect(JSON.parse(localStorage.getItem('orasec.plugins.v1') ?? 'null')).toEqual({ ora: false })
    setPlugins(null)
    expect(localStorage.getItem('orasec.plugins.v1')).toBeNull()
  })

  it('the Attacks tab goes only when every source that feeds it is off', () => {
    const allOff = Object.fromEntries(ATTACK_SOURCES.map((k) => [k, false]))
    expect(anyPluginOn(ATTACK_SOURCES, allOff)).toBe(false)
    expect(visibleTabs(allOff).map((t) => t.id)).toEqual(['home', 'vulns', 'governance', 'more'])
    expect(visibleTabs({ ...allOff, 'source.cloudflare': true }).map((t) => t.id)).toContain('attacks')
  })

  it('groups the plugin list in the order the server sent it', () => {
    const row = (key: string, group: string) => ({ key, name: key, group, on: true, available: true, active: true })
    const groups = groupPlugins([row('a', 'Data sources'), row('b', 'Data sources'), row('c', 'Assistant')])
    expect(groups.map((g) => [g.name, g.rows.map((r) => r.key)])).toEqual([
      ['Data sources', ['a', 'b']],
      ['Assistant', ['c']],
    ])
  })
})
