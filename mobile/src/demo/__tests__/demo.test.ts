import { afterEach, describe, expect, it, vi } from 'vitest'

import { api } from '@/api/http'
import type { Dashboard, FindingDetail, Page, FindingRow } from '@/api/orasec'
import { clearDeviceToken, setDeviceToken } from '@/api/session'
import { demoRequest } from '@/demo/demoApi'
import { DEMO_TOKEN, isDemoCode, isDemoToken } from '@/demo/session'
import { sizeFor } from '@/hooks/useLayout'

afterEach(async () => {
  vi.restoreAllMocks()
  await clearDeviceToken()
})

describe('demo session', () => {
  it('recognises only the demo token', () => {
    expect(isDemoToken(DEMO_TOKEN)).toBe(true)
    expect(isDemoToken('osm_realtokenrealtokenrealtoken')).toBe(false)
    expect(isDemoToken(null)).toBe(false)
  })

  it('rejects codes that are not the reviewer code', async () => {
    expect(await isDemoCode('ABCDE-FGHJK')).toBe(false)
    expect(await isDemoCode('short')).toBe(false)
    expect(await isDemoCode(undefined)).toBe(false)
  })

  it('answers every request locally and never calls the network', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    await setDeviceToken(DEMO_TOKEN)
    const me = await api<{ user: { name: string } }>('/me/')
    expect(me.user.name).toBe('Sam Carter')
    const dash = await api<Dashboard>('/dashboard/')
    expect(dash.posture.score).toBeGreaterThan(0)
    expect(dash.exploit.kev.length).toBeGreaterThan(0)
    await api('/ora/status/')
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('a wrong link code still goes to the server', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ error: 'Invalid code' }), { status: 400 }))
    await expect(api('/link/', { method: 'POST', body: { code: 'ABCDE-FGHJK' } })).rejects.toThrow('Invalid code')
    expect(fetchSpy).toHaveBeenCalledTimes(1)
  })
})

describe('demo data', () => {
  it('pages and filters findings', async () => {
    const all = await demoRequest<Page<FindingRow>>('/findings/?limit=25')
    expect(all.results).toHaveLength(25)
    expect(all.next).toBe(25)
    const kev = await demoRequest<Page<FindingRow>>('/findings/?kev=1&limit=25')
    expect(kev.total).toBeGreaterThan(0)
    expect(kev.results.every((f) => f.kev)).toBe(true)
    const closed = await demoRequest<Page<FindingRow>>('/findings/?status=closed&limit=25')
    expect(closed.results.every((f) => !f.active)).toBe(true)
  })

  it('keeps notes and resolutions in memory', async () => {
    const first = (await demoRequest<Page<FindingRow>>('/findings/?limit=1')).results[0]
    const noted = await demoRequest<FindingDetail>(`/findings/${first.id}/note/`, { method: 'POST', body: { text: 'checked' } })
    expect(noted.notes[0].text).toBe('checked')
    const closed = await demoRequest<FindingDetail>(`/findings/${first.id}/close/`, { method: 'POST', body: { reason: 'mitigated', note: 'patched' } })
    expect(closed.active).toBe(false)
    // leaving the demo restores the sample data
    await demoRequest('/logout/', { method: 'POST', body: {} })
    const again = await demoRequest<FindingDetail>(`/findings/${first.id}/`)
    expect(again.active).toBe(true)
    expect(again.notes.some((n) => n.text === 'checked')).toBe(false)
  })

  it('contains no real hosts, IP addresses, CVE ids or e-mail addresses', async () => {
    const blobs = [
      await demoRequest('/dashboard/'),
      await demoRequest('/findings/?status=all&limit=500'),
      await demoRequest('/attacks/?range=90d'),
      await demoRequest('/assets/'),
      await demoRequest('/risks/'),
      await demoRequest('/compliance/'),
      await demoRequest('/connectors/'),
      await demoRequest('/me/'),
    ]
    const text = JSON.stringify(blobs)
    const ips = text.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g) ?? []
    expect(ips.length).toBeGreaterThan(0)
    for (const ip of ips) expect(ip).toMatch(/^(192\.0\.2|198\.51\.100|203\.0\.113)\./)
    const cves = text.match(/CVE-\d{4}-\d+/g) ?? []
    expect(cves.length).toBeGreaterThan(0)
    for (const cve of cves) expect(cve.startsWith('CVE-2099-')).toBe(true)
    expect(text).not.toMatch(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/)
    const domains = text.match(/\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|nz|net|org|io|app)\b/g) ?? []
    for (const d of domains) expect(d).toMatch(/(^|\.)example\.com$/)
    expect(text.toLowerCase()).not.toContain('oraflows')
  })
})

describe('layout sizes', () => {
  it('maps widths to phone, tablet rail and wide sidebar', () => {
    expect(sizeFor(390)).toBe('phone')
    expect(sizeFor(599)).toBe('phone')
    expect(sizeFor(600)).toBe('tablet') // 7" tablet portrait
    expect(sizeFor(800)).toBe('tablet') // 10" tablet portrait
    expect(sizeFor(1032)).toBe('tablet') // iPad 13" portrait
    expect(sizeFor(1280)).toBe('wide') // 10" tablet landscape
    expect(sizeFor(1376)).toBe('wide') // iPad 13" landscape
  })
})

