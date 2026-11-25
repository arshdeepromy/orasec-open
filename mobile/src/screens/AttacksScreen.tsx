import { useState } from 'react'

import { errorMessage } from '@/api/http'
import { orasec } from '@/api/orasec'
import { Bars, ICONS, n, Panel, Stat, Tag, timeAgo } from '@/components/sec'
import { ErrorState, Screen, Segmented, SkeletonCards, StateBlock } from '@/components/ui/ds'
import { PullToRefresh } from '@/components/ui/PullToRefresh'
import { useLayout } from '@/hooks/useLayout'
import { useQuery } from '@/hooks/useQuery'

const RANGES = [
  { value: '24h', label: '24 h' },
  { value: '7d', label: '7 days' },
  { value: '30d', label: '30 days' },
  { value: '90d', label: '90 days' },
]

function label(iso: string, range: string): string {
  const d = new Date(iso)
  return range === '24h' || range === '7d'
    ? d.toLocaleString('en-NZ', { weekday: 'short', hour: 'numeric', hour12: true })
    : d.toLocaleDateString('en-NZ', { day: 'numeric', month: 'short' })
}

/** Blocked inbound traffic from the edge (Cloudflare) and firewalls (UniFi, OPNsense, AWS security groups). */
export default function AttacksScreen() {
  const [range, setRange] = useState('7d')
  const { isTablet } = useLayout()
  const { data, error, loading, reload } = useQuery((signal) => orasec.attacks(range, signal), [range])
  const blocked = data?.by_action.filter((a) => a.action !== 'alert' && a.action !== 'allow').reduce((t, a) => t + a.hits, 0) ?? 0

  return (
    <Screen title="Attacks" sub="Blocked at the edge and firewalls" large>
      <PullToRefresh onRefresh={reload}>
        <div className="stack">
          <Segmented options={RANGES} value={range} onChange={setRange} />
          {error && !data ? <ErrorState onRetry={reload} body={errorMessage(error)} /> : null}
          {loading && !data ? <SkeletonCards n={3} /> : null}
          {data ? (
            <div className="stack" style={{ opacity: loading ? 0.6 : 1 }}>
              <div className="stat-grid">
                <Stat label="Blocked" value={n(blocked || data.total)} sub={`${n(data.total)} events in total`} />
                <Stat label="Source IPs" value={n(data.unique_ips)} sub={`${data.countries.length} countries`} />
                <Stat
                  label="Top country"
                  value={data.countries[0] ? (<><span className="flag" aria-hidden="true">{data.countries[0].flag}</span> {data.countries[0].src_country}</>) : '—'}
                  sub={data.countries[0] ? `${n(data.countries[0].hits)} blocked` : 'No attacks'}
                />
                <Stat
                  label="Top blocker"
                  value={<span style={{ textTransform: 'capitalize', fontSize: 18 }}>{data.by_source[0]?.source ?? '—'}</span>}
                  sub={data.by_source[0] ? `${n(data.by_source[0].hits)} blocked` : ''}
                />
              </div>

              <Panel title="Over time" icon={ICONS.globe}>
                {data.timeline.length ? (
                  <>
                    <Bars values={data.timeline.map((t) => t.hits)} labels={data.timeline.map((t) => label(t.t, range))} height={isTablet ? 170 : 110} />
                    <div className="axis">
                      <span>{label(data.timeline[0].t, range)}</span>
                      <span>{label(data.timeline[data.timeline.length - 1].t, range)}</span>
                    </div>
                  </>
                ) : (
                  <p className="prose muted">No attacks recorded in this period.</p>
                )}
              </Panel>

              <div className="masonry">
              <Panel title="Where they come from" icon={ICONS.globe}>
                {data.countries.slice(0, 10).map((c) => (
                  <div key={c.src_country} className="row-kv">
                    <span className="k">
                      <span className="flag" aria-hidden="true">{c.flag}</span> {c.src_country}
                      <span style={{ color: 'var(--muted)', fontSize: 12 }}>{n(c.ips)} IPs</span>
                    </span>
                    <span className="v">{n(c.hits)}</span>
                  </div>
                ))}
                {!data.countries.length ? <p className="prose muted">—</p> : null}
              </Panel>

              <Panel title="Blocked by" icon={ICONS.shield}>
                {data.by_source.map((s) => (
                  <div key={s.source} className="row-kv">
                    <span className="k" style={{ textTransform: 'capitalize' }}>
                      {s.source}
                    </span>
                    <span className="v">{n(s.hits)}</span>
                  </div>
                ))}
              </Panel>

              <Panel title="Busiest attackers" icon={ICONS.skull}>
                {data.ips.length ? (
                  [...data.ips]
                    .sort((a, b) => b.hits - a.hits)
                    .slice(0, 12)
                    .map((ip) => (
                      <div key={ip.src_ip} className="note">
                        <div className="row-kv" style={{ border: 0, padding: 0 }}>
                          <span className="k mono-s">
                            <span className="flag" aria-hidden="true">{ip.flag}</span> {ip.src_ip}
                          </span>
                          <span className="v">{n(ip.hits)}</span>
                        </div>
                        <div className="who" style={{ marginTop: 3 }}>
                          {[ip.src_org, ip.ports.length ? `ports ${ip.ports.join(', ')}` : null, `last ${timeAgo(ip.last)}`].filter(Boolean).join(' · ')}
                        </div>
                      </div>
                    ))
                ) : (
                  <p className="prose muted">No individual IPs in this period (some sources report country totals only).</p>
                )}
              </Panel>

              <Panel title="Latest" icon={ICONS.bolt}>
                {data.recent.slice(0, 20).map((e, i) => (
                  <div key={`${e.t}-${i}`} className="note">
                    <div className="row-kv" style={{ border: 0, padding: 0 }}>
                      <span className="k mono-s">
                        <span className="flag" aria-hidden="true">{e.flag}</span> {e.ip ?? e.cc}
                        {e.port ? `:${e.port}` : ''}
                      </span>
                      <Tag tone={e.action === 'alert' ? 'warn' : 'ok'}>{e.action}</Tag>
                    </div>
                    <div className="who" style={{ marginTop: 3 }}>
                      {timeAgo(e.t)} · {e.source}
                      {e.target ? ` → ${e.target}` : ''}
                      {e.rule ? ` · ${e.rule}` : ''}
                    </div>
                  </div>
                ))}
                {!data.recent.length ? <StateBlock title="Quiet" body="Nothing blocked in this period." /> : null}
              </Panel>
              </div>
            </div>
          ) : null}
        </div>
      </PullToRefresh>
    </Screen>
  )
}

