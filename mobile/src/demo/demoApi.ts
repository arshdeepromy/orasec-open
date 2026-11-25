/**
 * Demo mode: answers the mobile API from the bundled, sanitised sample data in `./data.ts`.
 *
 * Used by App Review (a reviewer code in the private review notes) and for store screenshots. A demo session never
 * sends a request to an OraSec server: `api()` hands every request to `demoRequest` once the phone holds the demo
 * device token. Changes (notes, assign, resolve) live in memory until the app restarts.
 *
 * Only the SHA-256 of the reviewer code is in the app, so the code can't be read out of the bundle.
 */
import { ApiError } from '@/api/http'
import type { Dashboard, FindingDetail, FindingRow, LinkResult, Me, MyWork, Page, Severity } from '@/api/orasec'

import * as D from './data'

import { DEMO_TOKEN } from './session'

const SEV_ORDER: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Info']
const delay = (ms: number) => new Promise((r) => setTimeout(r, ms))

function findingsPage(params: URLSearchParams): Page<FindingRow> {
  const status = params.get('status') ?? 'open'
  const sev = params.get('severity')?.split(',').filter(Boolean) ?? []
  const q = (params.get('q') ?? '').toLowerCase()
  const asset = params.get('asset')
  const product = params.get('product')
  let rows = D.findings().filter((f) => (status === 'all' ? true : status === 'closed' ? !f.active : f.active))
  if (sev.length) rows = rows.filter((f) => sev.includes(f.severity))
  if (params.get('kev') === '1') rows = rows.filter((f) => f.kev)
  if (params.get('epss') === '1') rows = rows.filter((f) => (f.epss ?? 0) >= 0.1)
  if (params.get('overdue') === '1') rows = rows.filter((f) => f.overdue)
  if (params.get('mine') === '1') rows = rows.filter((f) => f.assigned_to_me)
  if (asset) rows = rows.filter((f) => f.assetKey === asset)
  if (product) rows = rows.filter((f) => f.product === product)
  if (q) rows = rows.filter((f) => `${f.title} ${f.component ?? ''} ${f.asset ?? ''} ${f.cve ?? ''}`.toLowerCase().includes(q))
  rows =
    params.get('sort') === 'newest'
      ? [...rows].sort((a, b) => (b.date ?? '').localeCompare(a.date ?? ''))
      : [...rows].sort((a, b) => (b.score ?? -1) - (a.score ?? -1) || SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity))
  const offset = Number(params.get('offset') ?? 0)
  const limit = Number(params.get('limit') ?? 25)
  const slice = rows.slice(offset, offset + limit)
  return { total: rows.length, offset, limit, next: offset + limit < rows.length ? offset + limit : null, results: slice.map(D.toRow) }
}

function finding(id: number) {
  const f = D.findings().find((x) => x.id === id)
  if (!f) throw new ApiError({ status: 404, message: 'Not found.' })
  return f
}

function oraReply(message: string) {
  const text = message.toLowerCase()
  const open = D.findings().filter((f) => f.active)
  if (text.includes('posture')) {
    const d = D.dashboard()
    return {
      text: `Posture is ${d.posture.score} of 1000 (sample data). The biggest drag is exposure: ${d.exploit.kev_cves} known-exploited CVEs are open on internet-facing services. ISO 27001 is at ${d.compliance.implemented} of ${d.compliance.applicable} controls implemented.`,
      items: [],
    }
  }
  const pick = text.includes('overdue') ? open.filter((f) => f.overdue) : open.filter((f) => f.kev || (f.epss ?? 0) >= 0.1)
  const top = [...pick].sort((a, b) => (b.score ?? 0) - (a.score ?? 0)).slice(0, 4)
  return {
    text: top.length
      ? `Fix these first. They are known or likely to be exploited, sit on exposed or critical assets, and are closest to their fix-by date. (This is the demo, so the answer comes from sample data.)`
      : 'Nothing matches right now.',
    items: top.map((f) => ({
      ref: f.cve ?? `#${f.id}`,
      kind: 'finding',
      title: f.title,
      severity: f.severity,
      band: f.band,
      kev: f.kev,
      due: f.due,
      overdue: f.overdue,
      asset: f.asset,
      path: `/finding/${f.id}`,
      why: f.kev ? 'Known exploited (CISA KEV)' : `EPSS ${Math.round((f.epss ?? 0) * 100)}%`,
    })),
  }
}

let oraNoticeAck = false
let oraHidden = false

/** Handles one mobile-API request in demo mode. `path` is relative to /api/v2/orasec/mobile (may carry a query). */
export async function demoRequest<T>(path: string, init: { method?: 'GET' | 'POST'; body?: unknown } = {}): Promise<T> {
  await delay(180)
  const [p, query = ''] = path.split('?')
  const params = new URLSearchParams(query)
  const body = (init.body ?? {}) as Record<string, unknown>
  const out = (v: unknown) => v as T
  let m: RegExpMatchArray | null

  if (p === '/link/') return out({ token: DEMO_TOKEN, device: D.DEMO_DEVICE, user: D.DEMO_USER } satisfies LinkResult)
  if (p === '/logout/') {
    D.resetDemoData()
    oraNoticeAck = false
    oraHidden = false
    return out({ ok: true })
  }
  if (p === '/me/') return out({ user: D.DEMO_USER, device: D.DEMO_DEVICE, server_time: new Date().toISOString(), min_app_version: '1.0.0', plugins: D.pluginMap() } satisfies Me)
  if (p === '/plugins/') return out({ plugins: D.plugins() })
  if (p === '/dashboard/') return out(D.dashboard() satisfies Dashboard)
  if (p === '/findings/') return out(findingsPage(params))
  if ((m = p.match(/^\/findings\/(\d+)\/$/))) return out(D.detail(finding(Number(m[1]))) satisfies FindingDetail)
  if ((m = p.match(/^\/findings\/(\d+)\/note\/$/))) {
    const f = finding(Number(m[1]))
    f.notes = [{ id: Date.now(), text: String(body.text ?? ''), author: D.DEMO_USER.name, date: new Date().toISOString() }, ...f.notes]
    return out(D.detail(f))
  }
  if ((m = p.match(/^\/findings\/(\d+)\/assign\/$/))) {
    const f = finding(Number(m[1]))
    f.assigned_to_me = !body.unassign
    f.assignee = body.unassign ? null : D.DEMO_USER.name
    return out(D.detail(f))
  }
  if ((m = p.match(/^\/findings\/(\d+)\/close\/$/))) {
    const f = finding(Number(m[1]))
    f.active = false
    f.mitigated = body.reason === 'mitigated'
    f.overdue = false
    f.mitigated_at = new Date().toISOString()
    f.mitigated_by = D.DEMO_USER.name
    f.notes = [{ id: Date.now(), text: String(body.note ?? ''), author: D.DEMO_USER.name, date: new Date().toISOString() }, ...f.notes]
    return out(D.detail(f))
  }
  if (p === '/assets/') {
    const q = (params.get('q') ?? '').toLowerCase()
    const rows = D.assetRows().filter((a) => !q || a.name.toLowerCase().includes(q))
    return out({ total: rows.length, results: rows })
  }
  if ((m = p.match(/^\/assets\/(.+)\/$/))) {
    const key = m[1].split('/').map(decodeURIComponent).join('/')
    const a = D.assetDetail(key)
    if (!a) throw new ApiError({ status: 404, message: 'Not found.' })
    return out(a)
  }
  if (p === '/attacks/') return out(D.attacks(params.get('range') ?? '7d'))
  if (p === '/code/') return out({ products: D.code(), categories: D.CODE_CATS })
  if (p === '/risks/') return out({ results: D.riskRows(), heat: D.heat() })
  if ((m = p.match(/^\/risks\/(\d+)\/$/))) {
    const r = D.riskDetail(Number(m[1]))
    if (!r) throw new ApiError({ status: 404, message: 'Not found.' })
    return out(r)
  }
  if (p === '/compliance/') return out(D.compliance())
  if (p === '/connectors/') return out(D.connectors())
  if (p === '/my-work/') {
    const open = D.findings().filter((f) => f.active)
    const mine = open.filter((f) => f.assigned_to_me || f.overdue)
    return out({
      counts: { mine: open.filter((f) => f.assigned_to_me).length, overdue: open.filter((f) => f.overdue).length, due7: 6 },
      results: mine.sort((a, b) => (b.score ?? 0) - (a.score ?? 0)).map(D.toRow),
    } satisfies MyWork)
  }

  /* Ora: a scripted helper; the demo never calls an AI provider. */
  const oraStatus = () => ({
    available: true,
    enabled: true,
    configured: true,
    hidden: oraHidden,
    notice_ack: oraNoticeAck,
    notice: 'This is the demo: Ora answers from the sample data with scripted replies.',
    memory_notice: null,
    first_name: D.DEMO_USER.name.split(' ')[0],
    superuser: true,
  })
  if (p === '/ora/status/') return out(oraStatus())
  if (p === '/ora/preference/') {
    if (typeof body.hidden === 'boolean') oraHidden = body.hidden
    if (typeof body.notice_ack === 'boolean') oraNoticeAck = body.notice_ack
    return out(oraStatus())
  }
  if (p === '/ora/chat/') {
    await delay(600)
    const reply = oraReply(String(body.message ?? ''))
    return out({
      conversation_id: 1,
      title: 'Demo chat',
      message: { id: Date.now(), role: 'assistant', text: reply.text, mood: 'happy', items: reply.items, suggestions: ['How is our security posture?', 'Any overdue findings?'] },
    })
  }
  if (p === '/ora/conversations/') return out({ results: [] })
  if (p === '/ora/memories/') return out({ results: [] })
  if (/^\/ora\/(memories\/forget|messages\/\d+\/feedback|conversations\/\d+\/delete)\/$/.test(p)) return out({ ok: true })

  /* Notifications: the demo has no server, so there is nothing to send them. */
  if (p === '/push/settings/') {
    return out({ available: false, registered: false, settings: { critical: true, approvals: true, alerts: true, overdue: true } })
  }

  throw new ApiError({ status: 404, message: 'Not available in the demo.' })
}

