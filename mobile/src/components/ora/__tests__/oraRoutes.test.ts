import { describe, expect, it } from 'vitest'
import { mobilePathFor } from '../OraSheet'

describe('mobilePathFor', () => {
  it('maps finding and risk detail pages to app screens', () => {
    expect(mobilePathFor('/finding/8807')).toBe('/vulns/8807')
    expect(mobilePathFor('/orasec/risks/3/')).toBe('/risks/3')
  })
  it('maps list pages and prefers the server app path', () => {
    expect(mobilePathFor('/orasec/attacks/')).toBe('/attacks')
    expect(mobilePathFor('/orasec/risks/', '/governance')).toBe('/governance')
  })
  it('returns null for web-only pages', () => {
    expect(mobilePathFor('/orasec/patching/')).toBeNull()
    expect(mobilePathFor(null)).toBeNull()
  })
})
