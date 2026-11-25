import type { ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'

import type { FindingRow, Severity } from '@/api/orasec'
import { I, Icon } from '@/components/ui/ds'

import '@/screens/orasec.css'

/* Shared OraSec building blocks: severity colours, bars, badges, number formatting. */

export const SEV_CLASS: Record<Severity, string> = { Critical: 's0', High: 's1', Medium: 's2', Low: 's3', Info: 's4' }
export const SEV_ORDER: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Info']

export const nf = new Intl.NumberFormat('en-NZ')
export const n = (v: number | null | undefined) => (v === null || v === undefined ? '—' : nf.format(v))
export const pct = (v: number | null | undefined, digits = 0) =>
  v === null || v === undefined ? '—' : `${(v * 100).toFixed(digits)}%`

/** Scanner text arrives as Markdown; the app shows it as plain readable text. */
export function plainText(md: string | null | undefined, max = 2500): string {
  if (!md) return ''
  return md
    .replace(/```[\s\S]*?```/g, (m) => m.replace(/```\w*\n?/g, ''))
    .replace(/`([^`]+)`/g, '$1')
    .replace(/\*\*([^*]+)\*\*/g, '$1')
    .replace(/__([^_]+)__/g, '$1')
    .replace(/(^|\s)\*([^*\n]+)\*/g, '$1$2')
    .replace(/!?\[([^\]]*)\]\(([^)]+)\)/g, (_m, t: string, u: string) => (t && t !== u ? `${t} (${u})` : u))
    .replace(/^#{1,6}\s+/gm, '')
    .replace(/^\s*[-*+]\s+/gm, '• ')
    .replace(/\n{3,}/g, '\n\n')
    .trim()
    .slice(0, max)
}

export function timeAgo(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return 'never'
  const s = Math.max(0, (now - new Date(iso).getTime()) / 1000)
  if (s < 60) return 'just now'
  if (s < 3600) return `${Math.round(s / 60)} min ago`
  if (s < 86400) return `${Math.round(s / 3600)} h ago`
  return `${Math.round(s / 86400)} d ago`
}

export function shortDate(iso: string | null | undefined): string {
  if (!iso) return '—'
  const d = new Date(iso.length === 10 ? `${iso}T00:00:00` : iso)
  return d.toLocaleDateString('en-NZ', { day: 'numeric', month: 'short', year: d.getFullYear() === new Date().getFullYear() ? undefined : 'numeric' })
}

export function SevDot({ s }: { s: Severity }) {
  return <i className={`sev-dot ${SEV_CLASS[s]}`} aria-hidden="true" />
}

export function SevBadge({ s }: { s: Severity }) {
  return <span className={`sev-badge ${SEV_CLASS[s]}`}>{s}</span>
}

export function Tag({ tone, children, title }: { tone: 'kev' | 'epss' | 'bad' | 'warn' | 'ok' | 'mut' | 'exp'; children: ReactNode; title?: string }) {
  return (
    <span className={`tag tag-${tone}`} title={title}>
      {children}
    </span>
  )
}

/** Composition bar: one segment per severity, widths relative to the row total. 2px gaps between fills. */
export function SevBar({ counts, total, height = 8 }: { counts: number[]; total?: number; height?: number }) {
  const sum = total ?? counts.reduce((a, b) => a + b, 0)
  const label = SEV_ORDER.map((s, i) => (counts[i] ? `${s} ${nf.format(counts[i])}` : null)).filter(Boolean).join(', ')
  return (
    <div className="sev-bar" style={{ height }} role="img" aria-label={label || 'No open findings'}>
      {sum > 0
        ? counts.map((c, i) => (c > 0 ? <span key={i} className={SEV_CLASS[SEV_ORDER[i]]} style={{ flexGrow: c }} /> : null))
        : null}
    </div>
  )
}

export function SevLegend() {
  return (
    <div className="sev-legend">
      {SEV_ORDER.map((s) => (
        <span key={s}>
          <SevDot s={s} />
          {s}
        </span>
      ))}
    </div>
  )
}

/** Card with a title row and optional "more" link. */
export function Panel({ title, icon, more, onMore, children, flush = false }: {
  title: string
  icon?: string
  more?: string
  onMore?: () => void
  children: ReactNode
  flush?: boolean
}) {
  return (
    <section className="card panel">
      <div className="panel-head">
        <h2>
          {icon ? <Icon d={icon} size={16} /> : null}
          {title}
        </h2>
        {more && onMore ? (
          <button className="panel-more" onClick={onMore}>
            {more}
            <Icon d={I.chevR} size={15} />
          </button>
        ) : null}
      </div>
      <div className={flush ? '' : 'panel-body'}>{children}</div>
    </section>
  )
}

/** Big number tile for the overview. */
export function Stat({ label, value, sub, tone, onClick }: {
  label: string
  value: ReactNode
  sub?: ReactNode
  tone?: 'alert' | 'ok'
  onClick?: () => void
}) {
  const Cmp = onClick ? 'button' : 'div'
  return (
    <Cmp className={`stat${tone ? ` ${tone}` : ''}`} onClick={onClick}>
      <span className="stat-l">{label}</span>
      <span className="stat-v">{value}</span>
      {sub ? <span className="stat-s">{sub}</span> : null}
    </Cmp>
  )
}

/** Posture ring (0–1000). */
export function Ring({ value, max = 1000, size = 64, label }: { value: number; max?: number; size?: number; label?: string }) {
  const p = Math.max(0, Math.min(1, value / max))
  const r = (size - (size > 90 ? 12 : 8)) / 2
  const c = 2 * Math.PI * r
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={label ?? `${value} of ${max}`}>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--card-2)" strokeWidth={size > 90 ? 11 : 7} />
      <circle
        cx={size / 2}
        cy={size / 2}
        r={r}
        fill="none"
        stroke="var(--accent)"
        strokeWidth={size > 90 ? 11 : 7}
        strokeLinecap="round"
        strokeDasharray={`${c * p} ${c}`}
        transform={`rotate(-90 ${size / 2} ${size / 2})`}
      />
      <text x="50%" y="50%" dominantBaseline="central" textAnchor="middle" className="ring-t" style={size > 90 ? { fontSize: Math.round(size / 4.2) } : undefined}>
        {value}
      </text>
    </svg>
  )
}

/** One finding in a list. */
export function FindingItem({ f, onSelect, selected = false }: { f: FindingRow; onSelect?: (id: number) => void; selected?: boolean }) {
  const navigate = useNavigate()
  return (
    <button
      className={`li finding-li${selected ? ' selected' : ''}`}
      aria-current={selected ? 'true' : undefined}
      data-testid={`finding-${f.id}`}
      onClick={() => (onSelect ? onSelect(f.id) : navigate(`/vulns/${f.id}`))}
    >
      <div className={`sev-stripe ${SEV_CLASS[f.severity]}`} aria-hidden="true" />
      <div className="body">
        <div className="t">{f.title}</div>
        <div className="s">
          {[f.asset?.replace(/^[^:]+:\s*/, ''), f.component && f.component_version ? `${f.component} ${f.component_version}` : f.component]
            .filter(Boolean)
            .join(' · ')}
        </div>
        <div className="finding-tags">
          <SevBadge s={f.severity} />
          {f.kev ? <Tag tone="kev">KEV</Tag> : null}
          {f.epss !== null && f.epss >= 0.1 ? <Tag tone="epss">EPSS {pct(f.epss)}</Tag> : null}
          {f.overdue ? <Tag tone="bad">Overdue</Tag> : f.due && f.active ? <Tag tone="mut">Due {shortDate(f.due)}</Tag> : null}
          {f.mitigated ? <Tag tone="ok">Fixed</Tag> : null}
        </div>
      </div>
      <span className="chev">
        <Icon d={I.chevR} size={19} />
      </span>
    </button>
  )
}

/** Simple vertical bar chart (one series). Each bar has a title for screen readers and long-press. */
export function Bars({ values, labels, height = 120, tone = 'accent', format = (v: number) => nf.format(v) }: {
  values: number[]
  labels: string[]
  height?: number
  tone?: 'accent' | 'warn'
  format?: (v: number) => string
}) {
  const max = Math.max(1, ...values)
  return (
    <div className="bars" style={{ height }} role="img" aria-label={labels.map((l, i) => `${l}: ${format(values[i])}`).join(', ')}>
      {values.map((v, i) => (
        <div key={i} className="bar-col" title={`${labels[i]}: ${format(v)}`}>
          <span className={`bar ${tone}`} style={{ height: `${Math.max(v > 0 ? 3 : 0, (v / max) * 100)}%` }} />
        </div>
      ))}
    </div>
  )
}

export const ICONS = {
  shield: 'M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z',
  bug: 'M12 12.75c1.148 0 2.278.08 3.383.237 1.037.146 1.866.966 1.866 2.013 0 3.728-2.35 6.75-5.25 6.75S6.75 18.728 6.75 15c0-1.046.83-1.867 1.866-2.013A24.204 24.204 0 0112 12.75zm0 0c2.883 0 5.647.508 8.207 1.44a23.91 23.91 0 01-1.152 6.06M12 12.75c-2.883 0-5.647.508-8.208 1.44.125 2.104.52 4.136 1.153 6.06M12 12.75a2.25 2.25 0 002.248-2.354M12 12.75a2.25 2.25 0 01-2.248-2.354M12 8.25c.995 0 1.971-.08 2.922-.236.403-.066.74-.358.795-.762a3.778 3.778 0 00-.399-2.25M12 8.25c-.995 0-1.97-.08-2.922-.236-.402-.066-.74-.358-.795-.762a3.734 3.734 0 01.4-2.253M12 8.25a2.25 2.25 0 00-2.248 2.146M12 8.25a2.25 2.25 0 012.248 2.146M8.683 5a6.032 6.032 0 01-1.155-1.002c.07-.63.27-1.222.574-1.747m.581 2.749A3.75 3.75 0 0115.318 5m0 0c.427-.283.815-.62 1.155-.999a4.471 4.471 0 00-.575-1.752M4.921 6a24.048 24.048 0 00-.392 3.314c1.668.546 3.416.914 5.223 1.082M19.08 6c.205 1.08.337 2.187.392 3.314a23.882 23.882 0 01-5.223 1.082',
  globe: 'M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418',
  scale: 'M12 3v17.25m0 0c-1.472 0-2.882.265-4.185.75M12 20.25c1.472 0 2.882.265 4.185.75M18.75 4.97A48.416 48.416 0 0012 4.5c-2.291 0-4.545.16-6.75.47m13.5 0c1.01.143 2.01.317 3 .52m-3-.52l2.62 10.726c.122.499-.106 1.028-.589 1.202a5.988 5.988 0 01-2.031.352 5.988 5.988 0 01-2.031-.352c-.483-.174-.711-.703-.59-1.202L18.75 4.971zm-16.5.52c.99-.203 1.99-.377 3-.52m0 0l2.62 10.726c.122.499-.106 1.028-.589 1.202a5.989 5.989 0 01-2.031.352 5.989 5.989 0 01-2.031-.352c-.483-.174-.711-.703-.59-1.202L5.25 4.971z',
  grid: 'M3.75 6A2.25 2.25 0 016 3.75h2.25A2.25 2.25 0 0110.5 6v2.25a2.25 2.25 0 01-2.25 2.25H6a2.25 2.25 0 01-2.25-2.25V6zM3.75 15.75A2.25 2.25 0 016 13.5h2.25a2.25 2.25 0 012.25 2.25V18a2.25 2.25 0 01-2.25 2.25H6A2.25 2.25 0 013.75 18v-2.25zM13.5 6a2.25 2.25 0 012.25-2.25H18A2.25 2.25 0 0120.25 6v2.25A2.25 2.25 0 0118 10.5h-2.25a2.25 2.25 0 01-2.25-2.25V6zM13.5 15.75a2.25 2.25 0 012.25-2.25H18a2.25 2.25 0 012.25 2.25V18A2.25 2.25 0 0118 20.25h-2.25A2.25 2.25 0 0113.5 18v-2.25z',
  server: 'M5.25 14.25h13.5m-13.5 0a3 3 0 01-3-3m3 3a3 3 0 100 6h13.5a3 3 0 100-6m-16.5-3a3 3 0 013-3h13.5a3 3 0 013 3m-19.5 0a4.5 4.5 0 01.9-2.7L5.737 5.1a3.375 3.375 0 012.7-1.35h7.126c1.062 0 2.062.5 2.7 1.35l2.587 3.45a4.5 4.5 0 01.9 2.7m0 0a3 3 0 01-3 3m0 3h.008v.008h-.008v-.008zm0-6h.008v.008h-.008v-.008zm-3 6h.008v.008h-.008v-.008zm0-6h.008v.008h-.008v-.008z',
  code: 'M17.25 6.75L22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3l-4.5 16.5',
  plug: 'M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m13.35-.622l1.757-1.757a4.5 4.5 0 00-6.364-6.364l-4.5 4.5a4.5 4.5 0 001.242 7.244',
  bolt: 'M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z',
  skull: 'M12 2a8 8 0 00-8 8c0 2.6 1.24 4.9 3.16 6.36V19a1 1 0 001 1h1.34v-2h1v2h2.99v-2h1v2h1.35a1 1 0 001-1v-2.64A7.98 7.98 0 0020 10a8 8 0 00-8-8zM9 13.5a1.75 1.75 0 110-3.5 1.75 1.75 0 010 3.5zm6 0a1.75 1.75 0 110-3.5 1.75 1.75 0 010 3.5z',
  stopwatch: 'M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z',
  link: 'M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m13.35-.622l1.757-1.757a4.5 4.5 0 00-6.364-6.364l-4.5 4.5a4.5 4.5 0 001.242 7.244',
  moon: 'M21.752 15.002A9.718 9.718 0 0118 15.75c-5.385 0-9.75-4.365-9.75-9.75 0-1.33.266-2.597.748-3.752A9.753 9.753 0 003 11.25C3 16.635 7.365 21 12.75 21a9.753 9.753 0 009.002-5.998z',
  info: 'M11.25 11.25l.041-.02a.75.75 0 011.063.852l-.708 2.836a.75.75 0 001.063.853l.041-.021M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9-3.75h.008v.008H12V8.25z',
  logout: 'M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15m3 0l3-3m0 0l-3-3m3 3H9',
}

