import { beforeEach, describe, expect, it } from 'vitest'

import {
  APPEARANCE_IDS,
  APPEARANCE_LABELS,
  mobileVariables,
  navActiveShadow,
  readCachedPreference,
  renderMobileAppearanceCss,
  resolveAppearance,
  tokensFor,
  writeCachedPreference,
} from './appearance'

describe('appearance', () => {
  beforeEach(() => localStorage.clear())

  it('has a label for every appearance and Auto', () => {
    for (const id of APPEARANCE_IDS) expect(APPEARANCE_LABELS[id]).toBeTruthy()
    expect(APPEARANCE_LABELS.auto).toBe('Auto')
    expect(APPEARANCE_IDS).toHaveLength(10)
  })

  it('maps every appearance to the core design-system variables', () => {
    for (const id of APPEARANCE_IDS) {
      const vars = new Map(mobileVariables(tokensFor(id)))
      for (const key of ['--accent', '--accent-on', '--text', '--muted', '--card', '--card-solid', '--page-bg', '--nav-bg']) {
        expect(vars.get(key), `${id} ${key}`).toBeTruthy()
      }
      expect(vars.get('color-scheme')).toBe(tokensFor(id).isDark ? 'dark' : 'light')
    }
  })

  it('renders one CSS block per appearance', () => {
    const css = renderMobileAppearanceCss()
    for (const id of APPEARANCE_IDS) expect(css).toContain(`[data-appearance="${id}"]`)
  })

  it('turns the web sidebar left bar into a ring for the bottom bar', () => {
    expect(navActiveShadow('inset 3px 0 0 #3ED6BC')).toBe('inset 0 0 0 1.5px #3ED6BC')
    expect(navActiveShadow('inset 0 0 0 1px rgba(255,255,255,0.18)')).toBe('inset 0 0 0 1px rgba(255,255,255,0.18)')
  })

  it('Auto follows the phone', () => {
    expect(resolveAppearance('auto', false)).toBe('oraflows')
    expect(resolveAppearance('auto', true)).toBe('dark')
    expect(resolveAppearance('vintage', true)).toBe('vintage')
  })

  it('defaults to Auto and caches the choice', () => {
    expect(readCachedPreference()).toBe('auto')
    writeCachedPreference('glass')
    expect(readCachedPreference()).toBe('glass')
    localStorage.setItem('orasec.appearance.v1', 'nonsense')
    expect(readCachedPreference()).toBe('auto')
  })
})
