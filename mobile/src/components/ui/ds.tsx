import type { ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'

/* ============================================================
   Design-system template components (from the design handoff).
   Screen · ListRow · Kpi · MetaRow · SectionLabel · StateBlock ·
   SkeletonRows · Segmented · Chips · AmountHero
   ============================================================ */

export function Icon({ d, size = 22, stroke = 1.8 }: { d: string; size?: number; stroke?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={stroke}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d={d} />
    </svg>
  )
}

export const I = {
  back: 'M15 19l-7-7 7-7',
  chevR: 'M9 5l7 7-7 7',
  chevD: 'M6 9l6 6 6-6',
  plus: 'M12 5v14M5 12h14',
  search: 'M21 21l-4.35-4.35M17 11a6 6 0 11-12 0 6 6 0 0112 0z',
  close: 'M18 6L6 18M6 6l12 12',
  doc: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z',
  user: 'M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z',
  users: 'M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z',
  briefcase: 'M21 13.255A23.931 23.931 0 0112 15c-3.183 0-6.22-.62-9-1.745M16 6V4a2 2 0 00-2-2h-4a2 2 0 00-2 2v2m8 0H8m8 0h2a2 2 0 012 2v6a2 2 0 01-2 2H6a2 2 0 01-2-2V8a2 2 0 012-2h2',
  card: 'M3 10h18M7 15h2m4 0h4M5 6h14a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2z',
  cash: 'M17 9V7a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2m2 4h10a2 2 0 002-2v-6a2 2 0 00-2-2H9a2 2 0 00-2 2v6a2 2 0 002 2zm7-5a2 2 0 11-4 0 2 2 0 014 0z',
  chart: 'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z',
  calendar: 'M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z',
  clock: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z',
  cog: 'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065zM15 12a3 3 0 11-6 0 3 3 0 016 0z',
  box: 'M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4',
  truck: 'M9 17a2 2 0 11-4 0 2 2 0 014 0zM19 17a2 2 0 11-4 0 2 2 0 014 0zM13 16V6a1 1 0 00-1-1H4a1 1 0 00-1 1v10a1 1 0 001 1h1m8-1a1 1 0 01-1 1H9m4-1V8a1 1 0 011-1h2.586a1 1 0 01.707.293l3.414 3.414a1 1 0 01.293.707V16a1 1 0 01-1 1h-1m-6-1a1 1 0 001 1h1M5 17a2 2 0 104 0m6 0a2 2 0 104 0',
  bell: 'M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9',
  alert: 'M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z',
  check: 'M5 13l4 4L19 7',
  camera: 'M3 9a2 2 0 012-2h.93a2 2 0 001.664-.89l.812-1.22A2 2 0 0110.07 4h3.86a2 2 0 011.664.89l.812 1.22A2 2 0 0018.07 7H19a2 2 0 012 2v9a2 2 0 01-2 2H5a2 2 0 01-2-2V9zM15 13a3 3 0 11-6 0 3 3 0 016 0z',
  send: 'M6 12L3.269 3.126A59.768 59.768 0 0121.485 12 59.77 59.77 0 013.27 20.876L5.999 12zm0 0h7.5',
  download: 'M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3',
  edit: 'M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z',
  trash: 'M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16',
  phone: 'M3 5a2 2 0 012-2h3.28a1 1 0 01.948.684l1.498 4.493a1 1 0 01-.502 1.21l-2.257 1.13a11.042 11.042 0 005.516 5.516l1.13-2.257a1 1 0 011.21-.502l4.493 1.498a1 1 0 01.684.949V19a2 2 0 01-2 2h-1C9.716 21 3 14.284 3 6V5z',
  mail: 'M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z',
  inbox: 'M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4',
  wrench: 'M11.42 15.17L17.25 21A2.652 2.652 0 0021 17.25l-5.877-5.877M11.42 15.17l2.496-3.03c.317-.384.74-.626 1.208-.766M11.42 15.17l-4.655 5.653a2.548 2.548 0 11-3.586-3.586l6.837-5.63m5.108-.233c.55-.164 1.163-.188 1.743-.14a4.5 4.5 0 004.486-6.336l-3.276 3.277a3.004 3.004 0 01-2.25-2.25l3.276-3.276a4.5 4.5 0 00-6.336 4.486c.091 1.076-.071 2.264-.904 2.95l-.102.085',
  home: 'M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-4 0a1 1 0 01-1-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 01-1 1',
  lock: 'M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z',
  refresh: 'M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15',
  filter: 'M12 3c2.755 0 5.455.232 8.083.678.533.09.917.556.917 1.096v1.044a2.25 2.25 0 01-.659 1.591l-5.432 5.432a2.25 2.25 0 00-.659 1.591v2.927a2.25 2.25 0 01-1.244 2.013L9.75 21v-6.568a2.25 2.25 0 00-.659-1.591L3.659 7.409A2.25 2.25 0 013 5.818V4.774c0-.54.384-1.006.917-1.096A48.32 48.32 0 0112 3z',
  dots: 'M12 5v.01M12 12v.01M12 19v.01',
}

/* ------- Screen shell ------- */
export function Screen({
  title,
  sub,
  large = false,
  back = false,
  actions,
  fab,
  children,
  padded = true,
  className = '',
}: {
  title: string
  sub?: string
  large?: boolean
  back?: boolean | string
  actions?: ReactNode
  fab?: ReactNode
  children: ReactNode
  padded?: boolean
  className?: string
}) {
  const navigate = useNavigate()
  const goBack = () => {
    if (typeof back === 'string') navigate(back)
    else navigate(-1)
  }
  return (
    <div className={`flex min-h-full flex-col ${className}`}>
      <header className={`navbar${large ? ' lg' : ''}`}>
        {large ? (
          <>
            {(back || actions) && (
            <div className="nav-row">
              {back ? (
                <button className="nav-btn" aria-label="Back" onClick={goBack}>
                  <Icon d={I.back} />
                </button>
              ) : null}
              <div className="nav-actions">{actions}</div>
            </div>
            )}
            <div className="nav-big">
              <h1>{title}</h1>
              {sub ? <div className="sub">{sub}</div> : null}
            </div>
          </>
        ) : (
          <div className="nav-row">
            {back ? (
              <button className="nav-btn" aria-label="Back" onClick={goBack}>
                <Icon d={I.back} />
              </button>
            ) : (
              <span style={{ width: 40 }} />
            )}
            <div className="nav-title">
              {title}
              {sub ? <span className="sub">{sub}</span> : null}
            </div>
            <div className="nav-actions" style={{ minWidth: 40, justifyContent: 'flex-end' }}>
              {actions}
            </div>
          </div>
        )}
      </header>
      {padded ? <div className="pad stack scroll-pad">{children}</div> : children}
      {fab}
    </div>
  )
}

export function Fab({
  label,
  icon = I.plus,
  onClick,
}: {
  label?: string
  icon?: string
  onClick: () => void
}) {
  return (
    <button className={`fab${label ? '' : ' round'}`} onClick={onClick} aria-label={label ?? 'Add'}>
      <Icon d={icon} size={21} stroke={2} />
      {label}
    </button>
  )
}

/* ------- List row ------- */
export function ListRow({
  onClick,
  av,
  avTone = 'tint',
  title,
  sub,
  amt,
  badge,
  badgeTone,
  chev = true,
}: {
  onClick?: () => void
  av?: ReactNode
  avTone?: 'tint' | 'neutral'
  title: ReactNode
  sub?: ReactNode
  amt?: ReactNode
  badge?: string
  badgeTone?: string
  chev?: boolean
}) {
  const Cmp = onClick ? 'button' : 'div'
  return (
    <Cmp className="li" onClick={onClick}>
      {av !== undefined ? <div className={`av ${avTone}`}>{av}</div> : null}
      <div className="body">
        <div className="t">{title}</div>
        {sub ? <div className="s">{sub}</div> : null}
      </div>
      {amt !== undefined || badge ? (
        <div className="end">
          {amt !== undefined ? <div className="amt">{amt}</div> : null}
          {badge ? <Badge tone={badgeTone ?? badge}>{badge}</Badge> : null}
        </div>
      ) : null}
      {chev && onClick ? (
        <span className="chev">
          <Icon d={I.chevR} size={19} />
        </span>
      ) : null}
    </Cmp>
  )
}

const TONE_MAP: Record<string, string> = {
  paid: 'paid', active: 'active', completed: 'completed', success: 'success', approved: 'approved',
  accepted: 'success', done: 'completed', converted: 'success', filed: 'success', reconciled: 'success',
  sent: 'sent', info: 'info', in_progress: 'inprogress', inprogress: 'inprogress', open: 'info',
  scheduled: 'info', submitted: 'info', invoiced: 'info', issued: 'sent',
  overdue: 'overdue', danger: 'danger', failed: 'failed', expired: 'expired', rejected: 'danger',
  declined: 'danger', void: 'danger', low: 'danger',
  draft: 'draft', neutral: 'neutral', cancelled: 'cancelled', inactive: 'neutral', archived: 'neutral',
  pending: 'pending', warn: 'warn', expiring: 'expiring', partial: 'pending', due: 'pending',
  on_hold: 'warn', hold: 'warn',
}

export function toneFor(status: string | undefined | null): string {
  if (!status) return 'neutral'
  const key = String(status).toLowerCase().replace(/[\s-]+/g, '_')
  return TONE_MAP[key] ?? 'neutral'
}

export function Badge({ tone, children }: { tone?: string; children: ReactNode }) {
  const cls = toneFor(tone ?? (typeof children === 'string' ? children : undefined))
  return (
    <span className={`badge ${cls}`}>
      <span className="bd" />
      {children}
    </span>
  )
}

/* ------- KPI ------- */
export function Kpi({
  label,
  value,
  icon,
  tone = 'blue',
  delta,
  deltaDir,
}: {
  label: string
  value: ReactNode
  icon?: string
  tone?: 'blue' | 'green' | 'amber' | 'red' | 'purple'
  delta?: string
  deltaDir?: 'up' | 'down'
}) {
  return (
    <div className="kpi">
      <div className="ktop">
        <span className="klabel">{label}</span>
        {icon ? (
          <span className={`ico ${tone}`}>
            <Icon d={icon} size={16} />
          </span>
        ) : null}
      </div>
      <div className="kval">{value}</div>
      {delta ? <span className={`kdelta ${deltaDir ?? 'up'}`}>{delta}</span> : null}
    </div>
  )
}

/* ------- misc ------- */
export function SectionLabel({ children }: { children: ReactNode }) {
  return <div className="section-label">{children}</div>
}

export function MetaRow({ k, v, mono = true }: { k: ReactNode; v: ReactNode; mono?: boolean }) {
  return (
    <div className="meta-row">
      <span className="k">{k}</span>
      <span className={`v${mono ? ' mono' : ''}`}>{v}</span>
    </div>
  )
}

export function AmountHero({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="amount-hero">
      <div className="lbl">{label}</div>
      <div className="val">{value}</div>
    </div>
  )
}

export function Segmented({
  options,
  value,
  onChange,
}: {
  options: { value: string; label: string }[]
  value: string
  onChange: (v: string) => void
}) {
  return (
    <div className="seg" role="tablist">
      {options.map((o) => (
        <button
          key={o.value}
          role="tab"
          aria-selected={o.value === value}
          className={o.value === value ? 'on' : ''}
          onClick={() => onChange(o.value)}
        >
          {o.label}
        </button>
      ))}
    </div>
  )
}

export function Chips({
  options,
  value,
  onChange,
}: {
  options: { value: string; label: string; count?: number }[]
  value: string
  onChange: (v: string) => void
}) {
  return (
    <div className="chips">
      {options.map((o) => (
        <button
          key={o.value}
          className={`chip${o.value === value ? ' on' : ''}`}
          onClick={() => onChange(o.value)}
        >
          {o.label}
          {o.count !== undefined ? <span className="n">{o.count}</span> : null}
        </button>
      ))}
    </div>
  )
}

/* ------- states ------- */
export function StateBlock({
  kind = 'empty',
  icon,
  title,
  body,
  action,
}: {
  kind?: 'empty' | 'error' | 'restricted'
  icon?: string
  title: string
  body?: string
  action?: ReactNode
}) {
  const iconCls = kind === 'error' ? 'state-ico err' : kind === 'restricted' ? 'state-ico neutral' : 'state-ico'
  const d = icon ?? (kind === 'error' ? I.alert : kind === 'restricted' ? I.lock : I.inbox)
  return (
    <div className="state">
      <div className={iconCls}>
        <Icon d={d} size={26} />
      </div>
      <h3>{title}</h3>
      {body ? <p>{body}</p> : null}
      {action}
    </div>
  )
}

export function ErrorState({ onRetry, body }: { onRetry?: () => void; body?: string }) {
  return (
    <StateBlock
      kind="error"
      title="Something went wrong"
      body={body ?? "We couldn't load this. Check your connection and try again."}
      action={
        onRetry ? (
          <button className="btn btn-ghost" onClick={onRetry}>
            <Icon d={I.refresh} size={18} />
            Try again
          </button>
        ) : undefined
      }
    />
  )
}

export function SkeletonRows({ rows = 6, av = true }: { rows?: number; av?: boolean }) {
  return (
    <div className="list" aria-hidden="true">
      {Array.from({ length: rows }).map((_, i) => (
        <div className="li" key={i}>
          {av ? <span className="sk sk-av" /> : null}
          <div className="body">
            <span className="sk sk-line" style={{ width: `${55 + ((i * 13) % 30)}%` }} />
            <span className="sk sk-line sm" style={{ width: `${30 + ((i * 7) % 25)}%` }} />
          </div>
          <span className="sk sk-line" style={{ width: 48 }} />
        </div>
      ))}
    </div>
  )
}

export function SkeletonCards({ n = 3 }: { n?: number }) {
  return (
    <div className="stack" aria-hidden="true">
      {Array.from({ length: n }).map((_, i) => (
        <div className="card card-pad" key={i}>
          <span className="sk sk-line" style={{ width: '40%' }} />
          <div style={{ height: 10 }} />
          <span className="sk sk-line" style={{ width: '70%' }} />
        </div>
      ))}
    </div>
  )
}

