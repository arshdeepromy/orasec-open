import { api } from '@/api/http'

/** Typed access to the OraSec mobile API (orasec/mobile/api.py on the server). */

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info'
export const SEVERITIES: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Info']

export type User = { id: number; username: string; name: string; email: string; superuser: boolean }
export type Device = { id: number; name: string; platform?: string; linked?: string }

export type LinkResult = { token: string; device: Device; user: User }
/** plugins: which integrations work on this server (absent on servers from before plugins existed). */
export type Me = {
  user: User
  device: Device
  server_time: string
  min_app_version: string
  push?: { available: boolean }
  plugins?: Record<string, boolean>
}

/** One integration on the server. on: switched on. available: the server is set up for it. active: both. */
export type PluginRow = { key: string; name: string; group: string; on: boolean; available: boolean; active: boolean }

/** The four kinds of notification a person can switch on or off (saved to the account). */
export type PushKind = 'critical' | 'approvals' | 'alerts' | 'overdue'
export const PUSH_KINDS: PushKind[] = ['critical', 'approvals', 'alerts', 'overdue']
export type PushSettings = Record<PushKind, boolean>
/** available: the server can send to this kind of phone. registered: the server has this phone's address. */
export type PushState = { available: boolean; registered: boolean; settings: PushSettings }

export type AssetRow = {
  key: string
  name: string
  kind: string
  where: string | null
  product: string | null
  sev: number[]
  total: number
  kev: number
  epss: number
  overdue: number
  criticality: number
  exposed: boolean
  oldest_days: number | null
  risk: number
  mix: string
  url: string
}

export type KevRow = {
  cve: string
  findings: number
  assets: number
  epss: number | null
  component: string | null
  severity: Severity
  name: string
  due: string | null
  ransomware: boolean
  overdue: boolean
}

export type EpssRow = { cve: string; epss: number; pct: number; findings: number; assets: number; component: string | null; kev: boolean }

export type CodeRow = {
  product: string
  open: number
  sev: number[]
  cats: number[]
  resolved: number
  resolved30: number
  fixed_pct: number | null
}

export type ResolutionRow = {
  severity: Severity
  closed: number
  mean: number | null
  median: number | null
  p90: number | null
  sla: number
  within_pct: number | null
  buckets: number[]
  open_age: number[]
}

export type RiskRow = {
  id: number
  ref: string
  title: string
  product: string | null
  likelihood: number
  impact: number
  score: number
  residual: number | null
  treatment: string
  status: string
  status_label: string
  owner: string | null
  review: string | null
  review_overdue: boolean
  open: boolean
}

export type HeatRow = { likelihood: number; cells: Array<{ n: number; lvl: 'lo' | 'md' | 'hi' }> }

export type Dashboard = {
  generated: string
  compute_ms: number | null
  posture: { score: number; vuln: number; compliance: number; hygiene: number; trend: Array<{ d: string; score: number }> }
  kpi: {
    open: number
    critical: number
    high: number
    new7: number
    resolved30: number
    resolved_total: number
    assets: number
    exposed: number
    scanned_assets: number
  }
  severity: Array<{ name: Severity; n: number }>
  bands: Array<{ name: string; n: number }>
  assets: AssetRow[]
  asset_count: number
  exploit: {
    kev_findings: number
    kev_cves: number
    kev_catalog: number
    ransomware: number
    epss_likely: number
    epss_likely_cves: number
    open_cves: number
    assets_affected: number
    assets_total: number
    epss_buckets: number[]
    kev: KevRow[]
    epss_top: EpssRow[]
  }
  attacks: {
    h24: number
    d7: number
    d30: number
    prev30: number
    alerts30: number
    ips7: number
    daily: Array<{ d: string; n: number }>
    by_source: Array<{ source: string; n: number }>
    countries: Array<{ cc: string; flag: string; n: number }>
    ports: Array<{ port: number; n: number }>
  }
  code: CodeRow[]
  code_cats: string[]
  resolution: ResolutionRow[]
  sla: { tracked: number; overdue: number; due7: number; within_pct: number | null; mttr: number | null; closed365: number }
  trend: Array<{ w: string; opened: number; closed: number }>
  risk: { total: number; open: number; high: number; review_overdue: number; heat: HeatRow[]; rows: RiskRow[] }
  compliance: { implemented: number; applicable: number; in_progress: number; pass: number; warn: number; fail: number; evidence: number; score: number }
  connectors: Array<{ name: string; kind: string; status: string; healthy: boolean; last: string | null }>
  feeds: Array<{ name: string; status: string; records: number; last: string | null }>
  fix_first: Array<{ component: string; findings: number; kev: number; critical: number; high: number; hosts: number; fix: string | null }>
}

export type FindingRow = {
  id: number
  title: string
  severity: Severity
  cve: string | null
  component: string | null
  component_version: string | null
  kev: boolean
  epss: number | null
  active: boolean
  mitigated: boolean
  date: string | null
  asset: string | null
  product: string | null
  band: string | null
  score: number | null
  due: string | null
  overdue: boolean
}

export type Note = { id: number; text: string; author: string; date: string }

export type FindingDetail = FindingRow & {
  description: string | null
  mitigation: string | null
  impact: string | null
  references: string | null
  cwe: number | null
  cvss: number | null
  epss_percentile: number | null
  ransomware: boolean
  file_path: string | null
  line: number | null
  fix_version: string | null
  verified: boolean
  false_positive: boolean
  risk_accepted: boolean
  scanner: string | null
  test_id: number | null
  created: string | null
  mitigated_at: string | null
  mitigated_by: string | null
  sla_basis: string | null
  assignee: string | null
  assigned_to_me: boolean
  notes: Note[]
  web_url: string
}

export type Page<T> = { total: number; offset: number; limit: number; next: number | null; results: T[] }

export type FindingFilters = {
  status?: 'open' | 'closed' | 'all'
  severity?: Severity[]
  kev?: boolean
  epss?: boolean
  overdue?: boolean
  mine?: boolean
  asset?: string
  product?: string
  q?: string
  sort?: 'priority' | 'newest'
}

export type AssetDetail = AssetRow & {
  inventory?: {
    id: number
    type: string
    hostname: string
    ip: string
    os: string
    vendor: string
    model: string
    online: boolean | null
    exposed: boolean
    criticality: number
    owner: string | null
    last_seen: string | null
    last_scanned: string | null
  }
  top_findings: FindingRow[]
}

export type Attacks = {
  range: string
  total: number
  unique_ips: number
  countries: Array<{ src_country: string; flag: string; hits: number; ips: number; last: string }>
  by_source: Array<{ source: string; hits: number; events: number }>
  by_action: Array<{ action: string; hits: number }>
  ips: Array<{ src_ip: string; src_country: string; flag: string; src_org: string; hits: number; last: string; ports: number[]; targets: string[]; rules: string[] }>
  timeline: Array<{ t: string; hits: number }>
  recent: Array<{ t: string; ip: string | null; cc: string; flag: string; source: string; action: string; target: string; port: number | null; rule: string; hits: number }>
}

export type RiskDetail = RiskRow & {
  description: string
  threat: string
  vulnerability: string
  treatment_plan: string
  controls: Array<{ ref: string; title: string }>
  findings: FindingRow[]
  updated: string
}

export type Compliance = {
  summary: { total: number; applicable: number; implemented: number; in_progress: number; not_started: number; auto_pass: number; auto_warn: number; auto_fail: number; evidence: number; score: number }
  categories: Array<{ category: string; total: number; implemented: number; fail: number; pass: number }>
  attention: Array<{ ref: string; title: string; category: string; auto_status: 'fail' | 'warn'; detail: string; status: string; owner: string | null; evaluated: string | null }>
}

export type Connector = {
  id: number
  name: string
  kind: string
  enabled: boolean
  status: string
  healthy: boolean
  /** False when an administrator turned this source's plugin off (absent on older servers). */
  plugin_on?: boolean
  last_run: string | null
  last_success: string | null
  message: string
  interval_minutes: number
}

export type MyWork = { counts: { mine: number; overdue: number; due7: number }; results: FindingRow[] }

function qs(params: Record<string, string | number | boolean | undefined>): string {
  const parts = Object.entries(params)
    .filter(([, v]) => v !== undefined && v !== '' && v !== false)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v === true ? '1' : String(v))}`)
  return parts.length ? `?${parts.join('&')}` : ''
}

export const orasec = {
  link: (code: string, deviceName: string, platform: string, appVersion: string) =>
    api<LinkResult>('/link/', { method: 'POST', body: { code, device_name: deviceName, platform, app_version: appVersion } }),
  logout: () => api<{ ok: boolean }>('/logout/', { method: 'POST', body: {} }),
  me: (signal?: AbortSignal) => api<Me>('/me/', { signal }),
  plugins: (signal?: AbortSignal) => api<{ plugins: PluginRow[] }>('/plugins/', { signal }),
  pushState: (signal?: AbortSignal) => api<PushState>('/push/settings/', { signal }),
  pushSaveSettings: (settings: Partial<PushSettings>) => api<PushState>('/push/settings/', { method: 'POST', body: settings }),
  pushRegister: (token: string) => api<PushState>('/push/register/', { method: 'POST', body: { token } }),
  pushUnregister: () => api<PushState>('/push/unregister/', { method: 'POST', body: {} }),
  pushTest: () => api<{ ok: boolean; detail: string }>('/push/test/', { method: 'POST', body: {} }),
  dashboard: (signal?: AbortSignal) => api<Dashboard & { pending?: boolean }>('/dashboard/', { signal }),
  findings: (f: FindingFilters, offset = 0, signal?: AbortSignal) =>
    api<Page<FindingRow>>(
      `/findings/${qs({
        status: f.status,
        severity: f.severity?.join(','),
        kev: f.kev,
        epss: f.epss,
        overdue: f.overdue,
        mine: f.mine,
        asset: f.asset,
        product: f.product,
        q: f.q,
        sort: f.sort,
        offset,
        limit: 25,
      })}`,
      { signal },
    ),
  finding: (id: number, signal?: AbortSignal) => api<FindingDetail>(`/findings/${id}/`, { signal }),
  addNote: (id: number, text: string) => api<FindingDetail>(`/findings/${id}/note/`, { method: 'POST', body: { text } }),
  closeFinding: (id: number, reason: 'mitigated' | 'false_positive' | 'out_of_scope', note: string) =>
    api<FindingDetail>(`/findings/${id}/close/`, { method: 'POST', body: { reason, note } }),
  assign: (id: number, unassign = false) => api<FindingDetail>(`/findings/${id}/assign/`, { method: 'POST', body: { unassign } }),
  assets: (q = '', signal?: AbortSignal) => api<{ total: number; results: AssetRow[] }>(`/assets/${qs({ q })}`, { signal }),
  asset: (key: string, signal?: AbortSignal) => api<AssetDetail>(`/assets/${key.split('/').map(encodeURIComponent).join('/')}/`, { signal }),
  attacks: (range: string, signal?: AbortSignal) => api<Attacks>(`/attacks/${qs({ range })}`, { signal }),
  code: (signal?: AbortSignal) => api<{ products: CodeRow[]; categories: string[] }>('/code/', { signal }),
  risks: (signal?: AbortSignal) => api<{ results: RiskRow[]; heat: HeatRow[] }>('/risks/', { signal }),
  risk: (id: number, signal?: AbortSignal) => api<RiskDetail>(`/risks/${id}/`, { signal }),
  compliance: (signal?: AbortSignal) => api<Compliance>('/compliance/', { signal }),
  connectors: (signal?: AbortSignal) =>
    api<{ connectors: Connector[]; feeds: Array<{ name: string; status: string; records: number; last: string | null }> }>('/connectors/', { signal }),
  myWork: (signal?: AbortSignal) => api<MyWork>('/my-work/', { signal }),
}

