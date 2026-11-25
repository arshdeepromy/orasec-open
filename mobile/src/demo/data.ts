/**
 * Sanitised demo data for App Review and store screenshots.
 *
 * Nothing here comes from a real OraSec instance: hosts and products are invented, IP addresses are from the
 * documentation ranges (RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), domains use example.com
 * (RFC 2606) and every CVE id uses the year 2099, which no real CVE has. Package names are ordinary open-source
 * packages so the screens read naturally.
 */
import type {
  AssetDetail,
  AssetRow,
  Attacks,
  CodeRow,
  Compliance,
  Connector,
  Dashboard,
  FindingDetail,
  FindingRow,
  HeatRow,
  PluginRow,
  RiskDetail,
  RiskRow,
  Severity,
  User,
  Device,
} from '@/api/orasec'

export const DEMO_USER: User = { id: 9001, username: 'sam.demo', name: 'Sam Carter', email: '', superuser: true }
export const DEMO_DEVICE: Device = { id: 9001, name: 'Demo device (sample data)', platform: 'demo', linked: new Date().toISOString() }

/* Deterministic pseudo-random numbers so every screenshot run shows the same data. */
function rng(seed: number) {
  let s = seed >>> 0
  return () => {
    s = (s + 0x6d2b79f5) >>> 0
    let t = s
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

const DAY = 86_400_000
const now = () => Date.now()
const iso = (msAgo: number) => new Date(now() - msAgo).toISOString()
const dateOnly = (daysFromNow: number) => new Date(now() + daysFromNow * DAY).toISOString().slice(0, 10)

/* ---------------- assets ---------------- */

type AssetSeed = { key: string; name: string; kind: string; where: string | null; product: string | null; crit: number; exposed: boolean; host?: string; ip?: string; os?: string; hw?: [string, string] }

const ASSET_SEEDS: AssetSeed[] = [
  { key: 'container:storefront-web', name: 'storefront-web', kind: 'Container', where: 'app-host-01', product: 'Storefront', crit: 5, exposed: true },
  { key: 'host:app-host-01', name: 'app-host-01', kind: 'Host', where: null, product: null, crit: 5, exposed: true, host: 'app-host-01', ip: '192.0.2.10', os: 'Ubuntu 24.04 LTS', hw: ['Demo Cloud', 'c7g.large'] },
  { key: 'container:payments-api', name: 'payments-api', kind: 'Container', where: 'app-host-01', product: 'Payments API', crit: 5, exposed: true },
  { key: 'container:pdf-renderer', name: 'pdf-renderer', kind: 'Container', where: 'app-host-02', product: 'Documents', crit: 3, exposed: false },
  { key: 'host:build-runner', name: 'build-runner', kind: 'Host', where: null, product: null, crit: 3, exposed: false, host: 'build-runner', ip: '192.0.2.24', os: 'Debian 13', hw: ['Generic', 'x86_64 VM'] },
  { key: 'code:example/storefront', name: 'example/storefront', kind: 'Code', where: 'GitHub', product: 'Storefront', crit: 4, exposed: false },
  { key: 'code:example/payments-api', name: 'example/payments-api', kind: 'Code', where: 'GitHub', product: 'Payments API', crit: 4, exposed: false },
  { key: 'host:edge-proxy', name: 'edge-proxy', kind: 'Host', where: null, product: null, crit: 4, exposed: true, host: 'edge-proxy', ip: '192.0.2.5', os: 'Ubuntu 24.04 LTS', hw: ['Demo Cloud', 't4g.small'] },
  { key: 'cloud:demo-account', name: 'demo-cloud-account', kind: 'Cloud', where: 'ap-southeast-2', product: null, crit: 4, exposed: false },
  { key: 'network:office-firewall', name: 'office-firewall', kind: 'Network', where: null, product: null, crit: 3, exposed: true, host: 'fw-01', ip: '192.0.2.1', os: 'Firewall OS 24.7', hw: ['Generic', 'Appliance'] },
]

/* ---------------- findings ---------------- */

type Comp = { name: string; version: string; fix: string | null; scanner: string; cwe: number | null }
const COMPONENTS: Comp[] = [
  { name: 'openssl', version: '3.0.13', fix: '3.0.15', scanner: 'Trivy', cwe: 787 },
  { name: 'libxml2', version: '2.12.6', fix: '2.12.9', scanner: 'Trivy', cwe: 416 },
  { name: 'nginx', version: '1.24.0', fix: '1.26.2', scanner: 'Trivy', cwe: 122 },
  { name: 'curl', version: '8.5.0', fix: '8.9.1', scanner: 'Trivy', cwe: 125 },
  { name: 'glibc', version: '2.39', fix: '2.39-0ubuntu8.3', scanner: 'Wazuh', cwe: 787 },
  { name: 'linux-image-generic', version: '6.8.0-40', fix: '6.8.0-45', scanner: 'Wazuh', cwe: 416 },
  { name: 'jackson-databind', version: '2.15.2', fix: '2.15.4', scanner: 'Dependabot', cwe: 502 },
  { name: 'lodash', version: '4.17.20', fix: '4.17.21', scanner: 'Dependabot', cwe: 1321 },
  { name: 'express', version: '4.18.2', fix: '4.21.0', scanner: 'Trivy', cwe: 601 },
  { name: 'pillow', version: '10.2.0', fix: '10.3.0', scanner: 'Trivy', cwe: 120 },
  { name: 'protobuf', version: '4.25.1', fix: '4.25.3', scanner: 'Dependabot', cwe: 400 },
  { name: 'chromium', version: '128.0.6613', fix: null, scanner: 'Trivy', cwe: 787 },
  { name: 'sudo', version: '1.9.15', fix: '1.9.16', scanner: 'Wazuh', cwe: 269 },
  { name: 'requests', version: '2.31.0', fix: '2.32.2', scanner: 'Dependabot', cwe: 670 },
]

const SLA: Record<Severity, number> = { Critical: 7, High: 30, Medium: 90, Low: 180, Info: 365 }
const BAND_FOR = (s: number) => (s >= 80 ? 'P1 · Fix now' : s >= 60 ? 'P2 · This week' : s >= 35 ? 'P3 · This month' : 'P4 · Backlog')

export type DemoFinding = FindingDetail & { assetKey: string }

function buildFindings(): DemoFinding[] {
  const r = rng(20261116)
  const out: DemoFinding[] = []
  const sevPick = (): Severity => {
    const x = r()
    return x < 0.12 ? 'Critical' : x < 0.42 ? 'High' : x < 0.8 ? 'Medium' : x < 0.95 ? 'Low' : 'Info'
  }
  const KEV_IDS = new Set([3, 11, 20, 41])
  for (let i = 0; i < 64; i++) {
    const comp = COMPONENTS[Math.floor(r() * COMPONENTS.length)]
    const asset = ASSET_SEEDS[Math.floor(r() * ASSET_SEEDS.length)]
    const kev = KEV_IDS.has(i)
    const severity: Severity = kev ? (i % 2 ? 'Critical' : 'High') : sevPick()
    const epssRaw = kev ? 0.4 + r() * 0.5 : r() < 0.15 ? 0.1 + r() * 0.3 : r() * 0.05
    const epss = Math.round(epssRaw * 1000) / 1000
    const maxAge = severity === 'Critical' ? 9 : severity === 'High' ? 38 : 75
    const ageDays = Math.floor(r() * maxAge) + 1
    const dueDays = SLA[severity] - ageDays
    const closed = i % 9 === 4
    const active = !closed
    const score = Math.min(99, Math.round((severity === 'Critical' ? 60 : severity === 'High' ? 45 : severity === 'Medium' ? 28 : 12) + (kev ? 30 : 0) + epss * 20 + (asset.exposed ? 8 : 0) + asset.crit))
    const cve = `CVE-2099-${String(10400 + i * 37).padStart(5, '0')}`
    const title = `${cve} in ${comp.name} ${comp.version}`
    out.push({
      id: 7100 + i,
      assetKey: asset.key,
      title,
      severity,
      cve,
      component: comp.name,
      component_version: comp.version,
      kev,
      epss,
      active,
      mitigated: closed,
      date: dateOnly(-ageDays),
      asset: `${asset.kind}: ${asset.name}`,
      product: asset.product,
      band: active ? BAND_FOR(score) : null,
      score: active ? score : null,
      due: active ? dateOnly(kev ? (i === 20 ? -2 : 2 + (i % 5)) : dueDays) : null,
      overdue: active && (kev ? i === 20 : dueDays < 0),
      description:
        `A sample vulnerability in ${comp.name} ${comp.version}. A remote attacker who can send crafted input to an affected service may cause memory corruption, which can lead to a crash or, in some configurations, code execution.\n\nThis is demo data: the identifier ${cve} is fictional.`,
      mitigation: comp.fix
        ? `Upgrade ${comp.name} to ${comp.fix} or later, rebuild the image and redeploy. OraSec reopens the finding automatically if the next scan still detects it.`
        : `No fixed version is available yet. Limit exposure (no direct internet access, least-privilege network rules) and re-check when the vendor publishes an update.`,
      impact: null,
      references: 'https://www.example.com/advisories/demo',
      cwe: comp.cwe,
      cvss: severity === 'Critical' ? 9.8 : severity === 'High' ? 7.5 : severity === 'Medium' ? 5.3 : 3.1,
      epss_percentile: Math.min(0.999, epss * 1.6 + 0.3),
      ransomware: kev && i === 11,
      file_path: asset.kind === 'Code' ? `package-lock.json` : null,
      line: null,
      fix_version: comp.fix,
      verified: true,
      false_positive: false,
      risk_accepted: false,
      scanner: comp.scanner,
      test_id: 1,
      created: iso(ageDays * DAY),
      mitigated_at: closed ? iso(Math.max(1, ageDays - 3) * DAY) : null,
      mitigated_by: closed ? 'Sam Carter' : null,
      sla_basis: kev ? 'Known exploited (CISA KEV): fix within 7 days' : `${severity} severity: ${SLA[severity]}-day SLA`,
      assignee: i % 4 === 0 && active ? 'Sam Carter' : i % 4 === 1 && active ? 'Alex Ngata' : null,
      assigned_to_me: i % 4 === 0 && active,
      notes:
        i === 3
          ? [
              { id: 1, text: 'Patched image built, waiting for the maintenance window tonight.', author: 'Alex Ngata', date: iso(5 * 3600_000) },
              { id: 2, text: 'Confirmed the service is reachable from the internet; raised to P1.', author: 'Sam Carter', date: iso(26 * 3600_000) },
            ]
          : [],
      web_url: `/finding/${7100 + i}`,
    })
  }
  return out
}

let FINDINGS: DemoFinding[] | null = null
/** Back to the original sample data (leaving the demo clears notes, assignments and resolutions). */
export function resetDemoData(): void {
  FINDINGS = null
}
export function findings(): DemoFinding[] {
  if (!FINDINGS) FINDINGS = buildFindings()
  return FINDINGS
}

export function toRow(f: DemoFinding): FindingRow {
  return {
    id: f.id,
    title: f.title,
    severity: f.severity,
    cve: f.cve,
    component: f.component,
    component_version: f.component_version,
    kev: f.kev,
    epss: f.epss,
    active: f.active,
    mitigated: f.mitigated,
    date: f.date,
    asset: f.asset,
    product: f.product,
    band: f.band,
    score: f.score,
    due: f.due,
    overdue: f.overdue,
  }
}

export function detail(f: DemoFinding): FindingDetail {
  const { assetKey: _assetKey, ...rest } = f
  void _assetKey
  return { ...rest, notes: [...rest.notes] }
}

const SEV_IDX: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 }

export function assetRows(): AssetRow[] {
  const open = findings().filter((f) => f.active)
  return ASSET_SEEDS.map((a) => {
    const mine = open.filter((f) => f.assetKey === a.key)
    const sev = [0, 0, 0, 0, 0]
    for (const f of mine) sev[SEV_IDX[f.severity]]++
    // Hosts carry many OS package findings that the sample list does not enumerate.
    const scale = a.kind === 'Host' ? 9 : a.kind === 'Container' ? 4 : 1
    const scaled = sev.map((n, i) => (i === 0 ? n : n * scale + (i === 2 ? scale * 3 : 0)))
    const total = scaled.reduce((t, n) => t + n, 0)
    const kev = mine.filter((f) => f.kev).length
    const overdue = mine.filter((f) => f.overdue).length
    const epss = mine.filter((f) => (f.epss ?? 0) >= 0.1).length
    const risk = kev * 40 + scaled[0] * 10 + scaled[1] * 3 + (a.exposed ? 25 : 0) + a.crit * 4
    return {
      key: a.key,
      name: a.name,
      kind: a.kind,
      where: a.where,
      product: a.product,
      sev: scaled,
      total,
      kev,
      epss,
      overdue,
      criticality: a.crit,
      exposed: a.exposed,
      oldest_days: total ? 40 + (a.name.length % 30) : null,
      risk,
      mix: '',
      url: '',
    }
  }).sort((x, y) => y.risk - x.risk)
}

export function assetDetail(key: string): AssetDetail | null {
  const row = assetRows().find((a) => a.key === key)
  const seed = ASSET_SEEDS.find((a) => a.key === key)
  if (!row || !seed) return null
  const top = findings()
    .filter((f) => f.active && f.assetKey === key)
    .sort((a, b) => (b.score ?? 0) - (a.score ?? 0))
    .slice(0, 6)
    .map(toRow)
  return {
    ...row,
    inventory: seed.host
      ? {
          id: 1,
          type: seed.kind,
          hostname: seed.host,
          ip: seed.ip ?? '',
          os: seed.os ?? '',
          vendor: seed.hw?.[0] ?? '',
          model: seed.hw?.[1] ?? '',
          online: true,
          exposed: seed.exposed,
          criticality: seed.crit,
          owner: 'Platform team',
          last_seen: iso(12 * 60_000),
          last_scanned: dateOnly(0),
        }
      : undefined,
    top_findings: top,
  }
}

/* ---------------- attacks ---------------- */

const COUNTRIES: Array<[string, string, number]> = [
  ['US', '', 31],
  ['CN', '', 19],
  ['NL', '', 12],
  ['DE', '', 9],
  ['SG', '', 8],
  ['BR', '', 7],
  ['IN', '', 6],
  ['RU', '', 5],
  ['GB', '', 4],
  ['VN', '', 3],
]
const SOURCES: Array<[string, number]> = [
  ['cloudflare', 61],
  ['firewall', 27],
  ['cloud security groups', 12],
]
const ORGS = ['Example Hosting', 'Demo Cloud', 'Sample Transit', 'Test Net Ltd', 'Placeholder ISP']
const TARGETS = ['shop.example.com', 'api.example.com', 'www.example.com', 'vpn.example.com']
const RULES = ['Managed rules · SQLi', 'Bot fight', 'Port scan', 'Geo block', 'Rate limit', 'SSH brute force']
const PORTS = [22, 443, 80, 3389, 8080, 5432, 23]

function docIp(i: number): string {
  const nets = ['192.0.2', '198.51.100', '203.0.113']
  return `${nets[i % 3]}.${(i * 37 + 11) % 250 + 2}`
}

export function dailyAttacks(days: number): Array<{ d: string; n: number }> {
  const r = rng(77)
  return Array.from({ length: days }, (_, k) => {
    const daysAgo = days - 1 - k
    const base = 2600 + Math.sin(k / 3) * 600 + r() * 900
    return { d: dateOnly(-daysAgo), n: Math.round(daysAgo === 5 ? base * 2.4 : base) }
  })
}

export function attacks(range: string): Attacks {
  const hours = range === '24h' ? 24 : range === '7d' ? 7 * 24 : range === '30d' ? 30 * 24 : 90 * 24
  const points = range === '24h' ? 24 : range === '7d' ? 28 : range === '30d' ? 30 : 45
  const r = rng(hours)
  const timeline = Array.from({ length: points }, (_, k) => {
    const msAgo = ((points - 1 - k) / points) * hours * 3600_000
    const hits = Math.round((hours / points) * (95 + Math.sin(k / 2.3) * 30 + r() * 45) * (k === points - 6 ? 2.6 : 1))
    return { t: iso(msAgo), hits }
  })
  const total = timeline.reduce((t, x) => t + x.hits, 0)
  const ipsCount = Math.round(Math.sqrt(total) * 3.1)
  const countries = COUNTRIES.map(([cc, flag, w]) => ({ src_country: cc, flag, hits: Math.round((total * w) / 104), ips: Math.max(1, Math.round((ipsCount * w) / 104)), last: iso(Math.floor(r() * 50) * 60_000) }))
  const by_source = SOURCES.map(([source, w]) => ({ source, hits: Math.round((total * w) / 100), events: Math.round((total * w) / 100 / 3) }))
  const ips = Array.from({ length: 14 }, (_, i) => {
    const c = COUNTRIES[i % COUNTRIES.length]
    return {
      src_ip: docIp(i),
      src_country: c[0],
      flag: c[1],
      src_org: ORGS[i % ORGS.length],
      hits: Math.round(total / (8 + i * 2.2)),
      last: iso((i * 7 + 3) * 60_000),
      ports: [PORTS[i % PORTS.length], PORTS[(i + 2) % PORTS.length]].slice(0, 1 + (i % 2)),
      targets: [TARGETS[i % TARGETS.length]],
      rules: [RULES[i % RULES.length]],
    }
  })
  const recent = Array.from({ length: 20 }, (_, i) => {
    const c = COUNTRIES[(i * 3) % COUNTRIES.length]
    const src = SOURCES[i % SOURCES.length][0]
    return {
      t: iso((i * 4 + 1) * 60_000),
      ip: docIp(i + 3),
      cc: c[0],
      flag: c[1],
      source: src,
      action: i % 7 === 3 ? 'alert' : 'block',
      target: TARGETS[i % TARGETS.length],
      port: PORTS[(i + 1) % PORTS.length],
      rule: RULES[(i + 2) % RULES.length],
      hits: 1 + (i % 4),
    }
  })
  return {
    range,
    total,
    unique_ips: ipsCount,
    countries,
    by_source,
    by_action: [
      { action: 'block', hits: Math.round(total * 0.96) },
      { action: 'alert', hits: Math.round(total * 0.04) },
    ],
    ips,
    timeline,
    recent,
  }
}

/* ---------------- risks ---------------- */

const RISK_SEEDS: Array<[string, string, number, number, number | null, string, string, string | null, number]> = [
  ['R-001', 'Known-exploited vulnerability on an internet-facing service', 4, 5, 8, 'Mitigate', 'treating', 'Payments API', 0],
  ['R-002', 'Ransomware on the build server spreads to production', 3, 5, 6, 'Mitigate', 'treating', null, 20],
  ['R-003', 'Leaked API key in a public repository', 3, 4, 4, 'Mitigate', 'open', 'Storefront', -3],
  ['R-004', 'Cloud account takeover through phishing', 2, 5, 4, 'Mitigate', 'treating', null, 40],
  ['R-005', 'Backups cannot be restored in time', 2, 4, 3, 'Mitigate', 'treating', null, 12],
  ['R-006', 'PDF renderer browser engine has no upstream fix', 3, 3, 6, 'Accept', 'accepted', 'Documents', 60],
  ['R-007', 'Single administrator for the firewall', 2, 3, null, 'Mitigate', 'open', null, -10],
  ['R-008', 'Supplier outage of the payment gateway', 2, 4, 6, 'Transfer', 'treating', 'Payments API', 90],
  ['R-009', 'Old laptop with local admin rights', 1, 3, 2, 'Avoid', 'closed', null, 120],
]

export function riskRows(): RiskRow[] {
  return RISK_SEEDS.map(([ref, title, l, i, residual, treatment, status, product, reviewIn], k) => ({
    id: 300 + k,
    ref,
    title,
    product,
    likelihood: l,
    impact: i,
    score: l * i,
    residual,
    treatment,
    status,
    status_label: status === 'treating' ? 'Treating' : status === 'open' ? 'Open' : status === 'accepted' ? 'Accepted' : 'Closed',
    owner: k % 3 === 0 ? 'Sam Carter' : k % 3 === 1 ? 'Alex Ngata' : 'Priya Shah',
    review: dateOnly(reviewIn),
    review_overdue: reviewIn < 0 && status !== 'closed',
    open: status !== 'closed',
  }))
}

export function heat(): HeatRow[] {
  const open = riskRows().filter((r) => r.open)
  return [5, 4, 3, 2, 1].map((likelihood) => ({
    likelihood,
    cells: [1, 2, 3, 4, 5].map((impact) => {
      const n = open.filter((r) => r.likelihood === likelihood && r.impact === impact).length
      const s = likelihood * impact
      return { n, lvl: s >= 15 ? 'hi' : s >= 8 ? 'md' : 'lo' } as const
    }),
  }))
}

export function riskDetail(id: number): RiskDetail | null {
  const r = riskRows().find((x) => x.id === id)
  if (!r) return null
  const linked = r.ref === 'R-001' ? findings().filter((f) => f.kev && f.active).map(toRow) : r.ref === 'R-006' ? findings().filter((f) => f.component === 'chromium' && f.active).slice(0, 3).map(toRow) : []
  return {
    ...r,
    description: `${r.title}. Sample risk for the demo register, assessed on a 5 × 5 likelihood and impact scale.`,
    threat: 'An external attacker scanning for known weaknesses, or an automated botnet.',
    vulnerability: 'Patching depends on manual rebuilds; some components have no upstream fix yet.',
    treatment_plan: 'Patch within the SLA, keep the service behind the web application firewall, and alert on exploitation attempts. Review monthly.',
    controls: [
      { ref: 'A.8.8', title: 'Management of technical vulnerabilities' },
      { ref: 'A.8.20', title: 'Networks security' },
      { ref: 'A.5.7', title: 'Threat intelligence' },
    ],
    findings: linked,
    updated: iso(2 * DAY),
  }
}

/* ---------------- compliance ---------------- */

export function compliance(): Compliance {
  const categories = [
    { category: 'Organisational (A.5)', total: 37, implemented: 29, fail: 0, pass: 6 },
    { category: 'People (A.6)', total: 8, implemented: 7, fail: 0, pass: 1 },
    { category: 'Physical (A.7)', total: 14, implemented: 11, fail: 0, pass: 0 },
    { category: 'Technological (A.8)', total: 34, implemented: 24, fail: 2, pass: 19 },
  ]
  return {
    summary: { total: 93, applicable: 91, implemented: 71, in_progress: 14, not_started: 6, auto_pass: 26, auto_warn: 3, auto_fail: 2, evidence: 412, score: 78 },
    categories,
    attention: [
      { ref: 'A.8.8', title: 'Management of technical vulnerabilities', category: 'Technological', auto_status: 'fail', detail: '1 known-exploited vulnerability is past its fix-by date.', status: 'Implemented', owner: 'Sam Carter', evaluated: iso(40 * 60_000) },
      { ref: 'A.8.13', title: 'Information backup', category: 'Technological', auto_status: 'fail', detail: 'No restore test recorded in the last 90 days.', status: 'In progress', owner: 'Alex Ngata', evaluated: iso(3 * 3600_000) },
      { ref: 'A.8.9', title: 'Configuration management', category: 'Technological', auto_status: 'warn', detail: '2 hosts drifted from the hardening baseline.', status: 'Implemented', owner: 'Priya Shah', evaluated: iso(5 * 3600_000) },
      { ref: 'A.5.23', title: 'Information security for use of cloud services', category: 'Organisational', auto_status: 'warn', detail: 'One cloud account has no budget alert configured.', status: 'In progress', owner: 'Sam Carter', evaluated: iso(9 * 3600_000) },
    ],
  }
}

/* ---------------- connectors ---------------- */

export function connectors(): { connectors: Connector[]; feeds: Array<{ name: string; status: string; records: number; last: string | null }> } {
  const c = (id: number, name: string, kind: string, healthy: boolean, minsAgo: number, interval: number, status = 'ok', message = ''): Connector => ({
    id,
    name,
    kind,
    enabled: true,
    status,
    healthy,
    last_run: iso(minsAgo * 60_000),
    last_success: iso((healthy ? minsAgo : minsAgo + 1440) * 60_000),
    message,
    interval_minutes: interval,
  })
  return {
    connectors: [
      c(1, 'Host agents', 'Wazuh', true, 12, 60),
      c(2, 'Container images', 'Trivy', true, 95, 1440),
      c(3, 'Code scanning', 'GitHub', true, 30, 360),
      c(4, 'Edge firewall', 'Cloudflare', true, 4, 15),
      c(5, 'Office firewall', 'Firewall syslog', true, 6, 15),
      c(6, 'Cloud security groups', 'Cloud flow logs', false, 190, 60, 'late', 'Last run took longer than expected; retrying on the next schedule.'),
      c(7, 'Static analysis', 'Semgrep', true, 300, 1440),
    ],
    feeds: [
      { name: 'KEV', status: 'ok', records: 1408, last: iso(3 * 3600_000) },
      { name: 'EPSS', status: 'ok', records: 289_114, last: iso(7 * 3600_000) },
    ],
  }
}

/* ---------------- code ---------------- */

export const CODE_CATS = ['SAST', 'Secrets', 'Dependencies', 'Containers', 'GitHub']
export function code(): CodeRow[] {
  return [
    { product: 'Storefront', open: 148, sev: [3, 22, 71, 44, 8], cats: [18, 1, 63, 59, 7], resolved: 412, resolved30: 57, fixed_pct: 74 },
    { product: 'Payments API', open: 96, sev: [2, 15, 48, 27, 4], cats: [11, 0, 41, 39, 5], resolved: 288, resolved30: 33, fixed_pct: 75 },
    { product: 'Documents', open: 61, sev: [1, 9, 30, 18, 3], cats: [4, 0, 12, 44, 1], resolved: 97, resolved30: 12, fixed_pct: 61 },
    { product: 'Internal tools', open: 23, sev: [0, 3, 11, 8, 1], cats: [6, 0, 9, 7, 1], resolved: 54, resolved30: 9, fixed_pct: 70 },
  ]
}

/* ---------------- dashboard ---------------- */

export function dashboard(): Dashboard {
  const all = findings()
  const open = all.filter((f) => f.active)
  const assets = assetRows()
  const totalOpen = assets.reduce((t, a) => t + a.total, 0)
  const sevTotals = [0, 1, 2, 3, 4].map((i) => assets.reduce((t, a) => t + a.sev[i], 0))
  const kev = open.filter((f) => f.kev)
  const epssLikely = open.filter((f) => (f.epss ?? 0) >= 0.1)
  const d30 = dailyAttacks(30)
  const sum = (xs: Array<{ n: number }>) => xs.reduce((t, x) => t + x.n, 0)
  const risks = riskRows()
  const comp = compliance()
  const con = connectors()
  return {
    generated: iso(2 * 60_000),
    compute_ms: 412,
    posture: {
      score: 742,
      vuln: 688,
      compliance: 781,
      hygiene: 803,
      trend: Array.from({ length: 12 }, (_, k) => ({ d: dateOnly(-(11 - k) * 7), score: 690 + k * 5 })),
    },
    kpi: { open: totalOpen, critical: sevTotals[0], high: sevTotals[1], new7: 38, resolved30: 127, resolved_total: 2_406, assets: assets.length, exposed: assets.filter((a) => a.exposed).length, scanned_assets: assets.length },
    severity: (['Critical', 'High', 'Medium', 'Low', 'Info'] as Severity[]).map((name, i) => ({ name, n: sevTotals[i] })),
    bands: [
      { name: 'P1 · Fix now', n: open.filter((f) => f.band?.startsWith('P1')).length },
      { name: 'P2 · This week', n: open.filter((f) => f.band?.startsWith('P2')).length * 3 },
      { name: 'P3 · This month', n: open.filter((f) => f.band?.startsWith('P3')).length * 9 },
      { name: 'P4 · Backlog', n: Math.max(0, totalOpen - 200) },
    ],
    assets,
    asset_count: assets.length,
    exploit: {
      kev_findings: kev.length,
      kev_cves: kev.length,
      kev_catalog: 1408,
      ransomware: kev.filter((f) => f.ransomware).length,
      epss_likely: epssLikely.length,
      epss_likely_cves: epssLikely.length,
      open_cves: 512,
      assets_affected: new Set([...kev, ...epssLikely].map((f) => f.assetKey)).size,
      assets_total: assets.length,
      epss_buckets: [402, 61, 22, 9, 4],
      kev: kev.map((f) => ({
        cve: f.cve ?? '',
        findings: 1,
        assets: 1,
        epss: f.epss,
        component: f.component,
        severity: f.severity,
        name: `${f.component} remote code execution (sample)`,
        due: f.due,
        ransomware: f.ransomware,
        overdue: f.overdue,
      })),
      epss_top: epssLikely
        .filter((f) => !f.kev)
        .sort((a, b) => (b.epss ?? 0) - (a.epss ?? 0))
        .slice(0, 5)
        .map((f) => ({ cve: f.cve ?? '', epss: f.epss ?? 0, pct: 0.97, findings: 1, assets: 1, component: f.component, kev: false })),
    },
    attacks: {
      h24: d30[29].n,
      d7: sum(d30.slice(-7)),
      d30: sum(d30),
      prev30: Math.round(sum(d30) * 0.88),
      alerts30: 412,
      ips7: 1_284,
      daily: d30,
      by_source: SOURCES.map(([source, w]) => ({ source, n: Math.round((sum(d30) * w) / 100) })),
      countries: COUNTRIES.slice(0, 6).map(([cc, flag, w]) => ({ cc, flag, n: Math.round((sum(d30) * w) / 104) })),
      ports: PORTS.slice(0, 5).map((port, i) => ({ port, n: 9000 - i * 1500 })),
    },
    code: code(),
    code_cats: CODE_CATS,
    resolution: [
      { severity: 'Critical', closed: 41, mean: 4.2, median: 3, p90: 8, sla: 7, within_pct: 88, buckets: [], open_age: [] },
      { severity: 'High', closed: 236, mean: 17.5, median: 14, p90: 33, sla: 30, within_pct: 91, buckets: [], open_age: [] },
      { severity: 'Medium', closed: 1_102, mean: 41, median: 36, p90: 84, sla: 90, within_pct: 94, buckets: [], open_age: [] },
      { severity: 'Low', closed: 897, mean: 60, median: 52, p90: 150, sla: 180, within_pct: 97, buckets: [], open_age: [] },
    ],
    sla: { tracked: totalOpen, overdue: open.filter((f) => f.overdue).length * 4, due7: 23, within_pct: 92, mttr: 11, closed365: 2_276 },
    trend: Array.from({ length: 8 }, (_, k) => ({ w: dateOnly(-(7 - k) * 7), opened: 60 + ((k * 13) % 25), closed: 70 + ((k * 17) % 30) })),
    risk: {
      total: risks.length,
      open: risks.filter((r) => r.open).length,
      high: risks.filter((r) => r.open && r.score >= 15).length,
      review_overdue: risks.filter((r) => r.review_overdue).length,
      heat: heat(),
      rows: risks,
    },
    compliance: {
      implemented: comp.summary.implemented,
      applicable: comp.summary.applicable,
      in_progress: comp.summary.in_progress,
      pass: comp.summary.auto_pass,
      warn: comp.summary.auto_warn,
      fail: comp.summary.auto_fail,
      evidence: comp.summary.evidence,
      score: comp.summary.score,
    },
    connectors: con.connectors.map((c) => ({ name: c.name, kind: c.kind, status: c.status, healthy: c.healthy, last: c.last_success })),
    feeds: con.feeds,
    fix_first: [
      { component: 'openssl', findings: 46, kev: 1, critical: 3, high: 12, hosts: 5, fix: '3.0.15' },
      { component: 'linux-image-generic', findings: 38, kev: 0, critical: 0, high: 9, hosts: 3, fix: '6.8.0-45' },
      { component: 'libxml2', findings: 21, kev: 1, critical: 1, high: 6, hosts: 4, fix: '2.12.9' },
      { component: 'curl', findings: 17, kev: 0, critical: 0, high: 5, hosts: 6, fix: '8.9.1' },
    ],
  }
}


// --- Plugins (what a server with a typical set of integrations reports) ---------------------------------------------
export function plugins(): PluginRow[] {
  const row = (key: string, name: string, group: string, on = true, available = true): PluginRow => ({ key, name, group, on, available, active: on && available })
  return [
    row('source.wazuh', 'Wazuh (SIEM / XDR)', 'Data sources'),
    row('source.opnsense', 'OPNsense firewall', 'Data sources'),
    row('source.cloudflare', 'Cloudflare (DNS, TLS, WAF, threats)', 'Data sources'),
    row('source.github', 'GitHub (repositories, Dependabot, code & secret scanning)', 'Data sources'),
    row('source.aws', 'AWS (inventory, security groups, CSPM)', 'Data sources', false),
    row('intel.kev', 'CISA known exploited vulnerabilities', 'Threat intelligence'),
    row('intel.epss', 'EPSS exploit prediction', 'Threat intelligence'),
    row('ora', 'Ora assistant', 'Assistant'),
    row('sso', 'Single sign-on (OpenID Connect)', 'Sign-in and apps', true, false),
    row('mobile', 'Mobile app', 'Sign-in and apps'),
    row('push', 'Phone notifications', 'Sign-in and apps'),
    row('jira', 'Jira', 'Tickets and messages', false),
  ]
}

export function pluginMap(): Record<string, boolean> {
  return Object.fromEntries(plugins().map((p) => [p.key, p.active]))
}
