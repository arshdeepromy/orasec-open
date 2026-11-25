import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'

import { orasec } from '@/api/orasec'
import { errorMessage } from '@/api/http'
import { Bars, ICONS, n, Panel, pct, Ring, SevBar, SevDot, SevLegend, shortDate, Stat, Tag, timeAgo } from '@/components/sec'
import { ErrorState, I, Icon, Screen, SkeletonCards } from '@/components/ui/ds'
import { PullToRefresh } from '@/components/ui/PullToRefresh'
import { useAuth } from '@/contexts/AuthContext'
import { useQuery } from '@/hooks/useQuery'

export default function OverviewScreen() {
  const navigate = useNavigate()
  const { user, offline } = useAuth()
  const { data, error, loading, reload } = useQuery((signal) => orasec.dashboard(signal), [])

  // The server builds the metrics in the background on first use: poll until they are ready.
  useEffect(() => {
    if (!data?.pending) return
    const t = window.setTimeout(reload, 2500)
    return () => window.clearTimeout(t)
  }, [data, reload])

  const first = user?.name?.split(/\s+/)[0]
  const d = data && !data.pending ? data : null

  return (
    <Screen
      title="Overview"
      sub={first ? `Kia ora, ${first}` : 'Security operations'}
      large
      actions={
        <button className="nav-btn" aria-label="Refresh" onClick={reload}>
          <Icon d={I.refresh} />
        </button>
      }
    >
      <PullToRefresh onRefresh={reload}>
        <div className="stack">
          {offline ? (
            <div className="callout warn">
              <Icon d={I.alert} size={18} />
              You're offline. Showing the last numbers OraSec sent.
            </div>
          ) : null}
          {error && !d ? <ErrorState onRetry={reload} body={errorMessage(error)} /> : null}
          {(loading && !d) || data?.pending ? <SkeletonCards n={4} /> : null}

          {d ? (
            <>
              <div className="ov-top">
              <div className="card card-pad hero-big" data-testid="posture-big">
                <div className="hero-l">Security posture</div>
                <Ring value={d.posture.score} size={148} label={`Posture score ${d.posture.score} of 1000`} />
                <div className="hero-s">out of 1000</div>
                <div className="parts">
                  <div><b>{d.posture.vuln}</b><span>Exposure</span></div>
                  <div><b>{d.posture.compliance}</b><span>ISO</span></div>
                  <div><b>{d.posture.hygiene}</b><span>Hygiene</span></div>
                </div>
              </div>
              <div className="card card-pad hero">
                <Ring value={d.posture.score} label={`Posture score ${d.posture.score} of 1000`} />
                <div style={{ minWidth: 0 }}>
                  <div className="hero-l">Security posture</div>
                  <div className="stat-v">
                    {d.posture.score}
                    <small>/ 1000</small>
                  </div>
                  <div className="hero-s">
                    Exposure {d.posture.vuln} · ISO {d.posture.compliance} · Hygiene {d.posture.hygiene}
                  </div>
                </div>
              </div>

              <div className="stat-grid">
                <Stat
                  label="Open vulnerabilities"
                  value={n(d.kpi.open)}
                  sub={`${n(d.kpi.critical)} critical · ${n(d.kpi.high)} high`}
                  onClick={() => navigate('/vulns')}
                />
                <Stat
                  label="Known exploited"
                  value={
                    <>
                      {d.exploit.kev_cves}
                      <small>CVEs</small>
                    </>
                  }
                  sub={`${d.exploit.kev_findings} findings · CISA KEV`}
                  tone={d.exploit.kev_cves ? 'alert' : 'ok'}
                  onClick={() => navigate('/vulns?kev=1')}
                />
                <Stat
                  label="Likely exploited"
                  value={
                    <>
                      {d.exploit.epss_likely_cves}
                      <small>CVEs</small>
                    </>
                  }
                  sub={`${d.exploit.epss_likely} findings, EPSS ≥ 10%`}
                  onClick={() => navigate('/vulns?epss=1')}
                />
                <Stat
                  label="Assets exposed"
                  value={
                    <>
                      {d.exploit.assets_affected}
                      <small>/ {d.exploit.assets_total}</small>
                    </>
                  }
                  sub="with exploitable vulns"
                  onClick={() => navigate('/assets')}
                />
                <Stat label="Attacks blocked · 24 h" value={n(d.attacks.h24)} sub={`${n(d.attacks.d7)} in 7 days`} onClick={() => navigate('/attacks')} />
                <Stat
                  label="Resolved · 30 d"
                  value={n(d.kpi.resolved30)}
                  sub={d.sla.mttr == null ? "MTTR —" : `MTTR ${d.sla.mttr} day${d.sla.mttr === 1 ? "" : "s"}`}
                  onClick={() => navigate('/vulns?status=closed')}
                />
                <Stat
                  label="Within SLA"
                  value={
                    <>
                      {d.sla.within_pct ?? '—'}
                      <small>%</small>
                    </>
                  }
                  sub={`${n(d.sla.overdue)} overdue · ${n(d.sla.due7)} due soon`}
                  tone={d.sla.overdue ? 'alert' : undefined}
                  onClick={() => navigate('/my-work')}
                />
                <Stat label="New · 7 days" value={n(d.kpi.new7)} sub={`${n(d.kpi.scanned_assets)} assets scanned`} onClick={() => navigate('/vulns?sort=newest')} />
              </div>
              </div>

              <div className="masonry m3">

              <Panel title="Criticality" icon={ICONS.bug} more="All" onMore={() => navigate('/vulns')}>
                <SevBar counts={d.severity.map((s) => s.n)} height={12} />
                <div className="mt-2">
                  {d.severity.map((s) => (
                    <button key={s.name} className="row-kv" style={{ width: '100%' }} onClick={() => navigate(`/vulns?severity=${s.name}`)}>
                      <span className="k">
                        <SevDot s={s.name} />
                        {s.name}
                      </span>
                      <span className="v">{n(s.n)}</span>
                    </button>
                  ))}
                </div>
                <div className="section-label" style={{ marginTop: 14 }}>
                  Priority (risk-based)
                </div>
                {d.bands.map((b) => (
                  <div key={b.name} className="row-kv">
                    <span className="k">{b.name}</span>
                    <span className="v">{n(b.n)}</span>
                  </div>
                ))}
              </Panel>

              <Panel title="Exploitable" icon={ICONS.bolt} more="Priority" onMore={() => navigate('/vulns?kev=1')}>
                <p className="prose muted" style={{ fontSize: 13 }}>
                  {d.exploit.kev_cves} of {n(d.exploit.kev_catalog)} known-exploited CVEs affect you, across {d.exploit.assets_affected}{' '}
                  asset{d.exploit.assets_affected === 1 ? '' : 's'}.
                </p>
                <div className="mt-2">
                  {d.exploit.kev.slice(0, 6).map((k) => (
                    <button key={k.cve} className="row-kv" style={{ width: '100%', alignItems: 'flex-start' }} onClick={() => navigate(`/vulns?q=${k.cve}`)}>
                      <span className="k" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: 4, whiteSpace: 'normal' }}>
                        <span className="mono-s">{k.cve}</span>
                        <span style={{ fontSize: 12.5, color: 'var(--muted)' }}>{k.name || k.component}</span>
                      </span>
                      <span style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4 }}>
                        <Tag tone="kev">KEV</Tag>
                        {k.due ? <Tag tone={k.overdue ? 'bad' : 'warn'}>Due {shortDate(k.due)}</Tag> : null}
                      </span>
                    </button>
                  ))}
                  {d.exploit.epss_top
                    .filter((e) => !e.kev)
                    .slice(0, 3)
                    .map((e) => (
                      <button key={e.cve} className="row-kv" style={{ width: '100%' }} onClick={() => navigate(`/vulns?q=${e.cve}`)}>
                        <span className="k">
                          <span className="mono-s">{e.cve}</span>
                        </span>
                        <Tag tone="epss">EPSS {pct(e.epss)}</Tag>
                      </button>
                    ))}
                  {!d.exploit.kev.length && !d.exploit.epss_top.length ? <p className="prose muted">Nothing known or likely exploited is open.</p> : null}
                </div>
              </Panel>

              <Panel title="Most at-risk assets" icon={ICONS.server} more={`All ${d.asset_count}`} onMore={() => navigate('/assets')} flush>
                <div className="list flush" style={{ border: 0 }}>
                  {d.assets.slice(0, 5).map((a) => (
                    <button key={a.key} className="li asset-li" onClick={() => navigate(`/assets/${encodeURIComponent(a.key)}`)}>
                      <div className="body">
                        <div className="t">
                          {a.name}
                          {a.exposed ? <Tag tone="exp">Internet</Tag> : null}
                        </div>
                        <div className="s">
                          {a.kind}
                          {a.product ? ` · ${a.product}` : ''} · {n(a.total)} open
                        </div>
                        <SevBar counts={a.sev} />
                      </div>
                      <div className="end">
                        {a.kev ? <Tag tone="kev">{a.kev} KEV</Tag> : null}
                        {a.overdue ? <Tag tone="bad">{a.overdue} overdue</Tag> : null}
                      </div>
                    </button>
                  ))}
                </div>
                <div className="pad-x" style={{ paddingBottom: 12 }}>
                  <SevLegend />
                </div>
              </Panel>

              <Panel title="Attacks blocked · 30 days" icon={ICONS.globe} more="Details" onMore={() => navigate('/attacks')}>
                <div className="stat-v">{n(d.attacks.d30)}</div>
                <div className="hero-s" style={{ marginBottom: 10 }}>
                  {n(d.attacks.ips7)} source IPs this week
                  {d.attacks.countries[0] ? (
                    <>
                      {' · most from '}
                      <span className="flag" aria-hidden="true">{d.attacks.countries[0].flag}</span> {d.attacks.countries[0].cc}
                    </>
                  ) : null}
                </div>
                <Bars values={d.attacks.daily.map((x) => x.n)} labels={d.attacks.daily.map((x) => shortDate(x.d))} height={90} />
                <div className="axis">
                  <span>{shortDate(d.attacks.daily[0]?.d)}</span>
                  <span>today</span>
                </div>
              </Panel>

              <Panel title="Code vulnerabilities" icon={ICONS.code} more="By product" onMore={() => navigate('/code')}>
                {d.code.length ? (
                  d.code.map((c) => (
                    <div key={c.product} style={{ padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
                      <div className="row-kv" style={{ border: 0, padding: '0 0 6px' }}>
                        <span className="k">{c.product}</span>
                        <span className="v">{n(c.open)} open</span>
                      </div>
                      <SevBar counts={c.sev} />
                      <div className="hero-s">
                        {n(c.resolved)} resolved · {n(c.resolved30)} in 30 days
                      </div>
                    </div>
                  ))
                ) : (
                  <p className="prose muted">No code scans yet.</p>
                )}
              </Panel>

              <Panel title="Resolution time" icon={ICONS.stopwatch}>
                {d.resolution.slice(0, 4).map((r) => (
                  <div key={r.severity} className="row-kv">
                    <span className="k">
                      <SevDot s={r.severity} />
                      {r.severity}
                      <span style={{ color: 'var(--muted)', fontSize: 12 }}>SLA {r.sla} d</span>
                    </span>
                    <span className={`v${r.median === null ? ' muted' : ''}`}>
                      {r.median === null ? 'no fixes yet' : `${r.median} d median`}
                      {r.within_pct !== null ? ` · ${r.within_pct}%` : ''}
                    </span>
                  </div>
                ))}
              </Panel>

              {d.fix_first.length ? (
                <Panel title="Fix first" icon={ICONS.shield} more="All" onMore={() => navigate('/vulns')}>
                  {d.fix_first.map((f) => (
                    <button key={f.component} className="row-kv" style={{ width: '100%' }} onClick={() => navigate(`/vulns?q=${encodeURIComponent(f.component)}`)}>
                      <span className="k">
                        {f.component}
                        {f.kev ? <Tag tone="kev">KEV</Tag> : null}
                      </span>
                      <span className="v muted">{n(f.findings)} findings</span>
                    </button>
                  ))}
                </Panel>
              ) : null}

              <Panel title="Governance" icon={ICONS.scale} more="Open" onMore={() => navigate('/governance')}>
                <div className="row-kv">
                  <span className="k">Open risks</span>
                  <span className="v">
                    {d.risk.open}
                    {d.risk.high ? ` · ${d.risk.high} high` : ''}
                  </span>
                </div>
                <div className="row-kv">
                  <span className="k">ISO 27001 controls implemented</span>
                  <span className="v">
                    {d.compliance.implemented} / {d.compliance.applicable}
                  </span>
                </div>
                <div className="row-kv">
                  <span className="k">Automated checks</span>
                  <span className="v">
                    {d.compliance.pass} pass · {d.compliance.fail} fail
                  </span>
                </div>
                <button className="row-kv" style={{ width: '100%' }} onClick={() => navigate('/connectors')}>
                  <span className="k">Connectors healthy</span>
                  <span className="v">
                    {d.connectors.filter((c) => c.healthy).length} / {d.connectors.length}
                  </span>
                </button>
              </Panel>

              </div>

              <div className="updated">Updated {timeAgo(d.generated)}</div>
            </>
          ) : null}
        </div>
      </PullToRefresh>
    </Screen>
  )
}

