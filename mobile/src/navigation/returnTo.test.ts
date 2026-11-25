import { beforeEach, describe, expect, it } from 'vitest'

import { rememberReturnTo, takeReturnTo } from './returnTo'

describe('returnTo', () => {
  beforeEach(() => sessionStorage.clear())
  it('returns the remembered in-app path once', () => {
    rememberReturnTo('/sign/abc')
    expect(takeReturnTo()).toBe('/sign/abc')
    expect(takeReturnTo()).toBe('/')
  })
  it('ignores unsafe or auth paths', () => {
    for (const p of ['https://evil.example', '//evil.example', '/login', '/two-factor', 42]) {
      rememberReturnTo(p)
      expect(takeReturnTo()).toBe('/')
    }
  })
})
