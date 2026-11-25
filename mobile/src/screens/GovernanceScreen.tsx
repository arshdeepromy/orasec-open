import { useNavigate, useSearchParams } from 'react-router-dom'

import { errorMessage } from '@/api/http'
import { orasec } from '@/api/orasec'
import { ICONS, n, Panel, Stat, Tag, timeAgo } from '@/components/sec'
import { ErrorState, Screen, Segmented, SkeletonCards, StateBlock } from '@/components/ui/ds'
import { PullToRefresh } from '@/components/ui/PullToRefresh'
import { webAppUrl } from '@/config/serverConfig'
import { useQuery } from '@/hooks/useQuery'
import { openExternalUrl } from '@/native/browser'

export default function GovernanceScreen() {
  const [params, setParams] = useSearchParams()
  const tab = params.get('tab') === 'iso' ? 'iso' : 'risks'
  const change = (v: string) => setParams(v === 'iso' ? { tab: 'iso' } : {}, { replace: true })
  return (
    <Screen title="Governance" sub="Risk register and ISO/IEC 27001" large>
      <div className="stack">
        <Segmented
          options={[
            { value: 'risks', label: 'Risk register' },
            { value: 'iso', label: 'ISO 27001' },
          ]}
          value={tab}
          onChange={change}
        />
        {tab === 'risks' ? <Risks /> : <Iso />}
      </div>
    </Screen>
  )
}

function Risks() {
  const navigate = useNavigate()
  const { data, error, loading, reload } = useQuery((signal) => orasec.risks(signal), [])
  const open = data?.results.filter((r) => r.open) ?? []
  return (
    <PullToRefresh onRefresh={reload}>
      <div className="stack">
        {error && !data ? <ErrorState onRetry={reload} body={errorMessage(error)} /> : null}
        {loading && !data ? <SkeletonCards n={2} /> : null}
        {data ? (
          <>
            <div className="t-2col">
            <div className="col">
            <div className="stat-grid" style={{ gridTemplateColumns: 'repeat(2, minmax(0, 1fr))' }}>
              <Stat label="Open risks" value={open.length} sub={`${data.results.length} in the register`} />
              <Stat label="High (score ≥ 15)" value={open.filter((r) => r.score >= 15).length} tone={open.some((r) => r.score >= 15) ? 'alert' : undefined} sub={`${open.filter((r) => r.review_overdue).length} reviews overdue`} />
            </div>
            <Panel title="Heat map" icon={ICONS.grid}>
              <div className="heat" role="img" aria-label="Open risks by likelihood and impact">
                {data.heat.map((row) => (
                  <div key={row.likelihood} style={{ display: 'contents' }}>
                    <span className="ax">{row.likelihood}</span>
                    {row.cells.map((c, i) => (
                      <div key={i} className={`c${c.n ? ` ${c.lvl}` : ''}`}>
                        {c.n || ''}
                      </div>
                    ))}
                  </div>
                ))}
                <span className="ax" />
                {[1, 2, 3, 4, 5].map((i) => (
                  <span key={i} className="ax">
                    {i}
                  </span>
                ))}
              </div>
              <p className="hero-s" style={{ textAlign: 'center' }}>
                Impact → · ↑ Likelihood
              </p>
            </Panel>
            </div>
            <div className="col">
            {data.results.length ? (
              <div className="list">
                {data.results.map((r) => (
                  <button key={r.id} className="li" onClick={() => navigate(`/risks/${r.id}`)} data-testid={`risk-${r.id}`}>
                    <div className={`av ${r.score >= 15 ? 'tint' : 'neutral'}`} style={{ fontFamily: 'var(--mono)' }}>
                      {r.score}
                    </div>
                    <div className="body">
                      <div className="t">{r.title}</div>
                      <div className="s">
                        {r.ref} · {r.treatment} · {r.owner ?? 'No owner'}
                      </div>
                    </div>
                    <div className="end">
                      <Tag tone={r.open ? (r.review_overdue ? 'bad' : 'mut') : 'ok'}>{r.review_overdue ? 'Review due' : r.status_label}</Tag>
                    </div>
                  </button>
                ))}
              </div>
            ) : (
              <StateBlock
                title="No risks recorded yet"
                body="Record the top risks (for example the known-exploited vulnerabilities) in OraSec on the web, so owners and treatments are tracked for ISO 27001 clause 6.1."
                action={
                  <button className="btn btn-ghost" onClick={() => void openExternalUrl(webAppUrl('/orasec/risks/new/'))}>
                    Add a risk on the web
                  </button>
                }
              />
            )}
            </div>
            </div>
          </>
        ) : null}
      </div>
    </PullToRefresh>
  )
}

function Iso() {
  const { data, error, loading, reload } = useQuery((signal) => orasec.compliance(signal), [])
  const s = data?.summary
  return (
    <PullToRefresh onRefresh={reload}>
      <div className="stack">
        {error && !data ? <ErrorState onRetry={reload} body={errorMessage(error)} /> : null}
        {loading && !data ? <SkeletonCards n={2} /> : null}
        {s && data ? (
          <>
            <div className="stat-grid">
              <Stat label="ISO score" value={<>{s.score}<small>%</small></>} sub={`${n(s.evidence)} evidence items`} />
              <Stat label="Not started" value={s.not_started} sub={`${s.applicable} applicable controls`} />
              <Stat label="Implemented" value={<>{s.implemented}<small>/ {s.applicable}</small></>} sub={`${s.in_progress} in progress`} />
              <Stat label="Automated checks" value={<>{s.auto_pass}<small>pass</small></>} sub={`${s.auto_warn} warn · ${s.auto_fail} fail`} tone={s.auto_fail ? 'alert' : undefined} />
            </div>
            <div className="t-2col">
            <Panel title="By theme" icon={ICONS.scale}>
              {data.categories.map((c) => (
                <div key={c.category} style={{ padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
                  <div className="row-kv" style={{ border: 0, padding: '0 0 6px' }}>
                    <span className="k">{c.category}</span>
                    <span className="v">
                      {c.implemented} / {c.total}
                    </span>
                  </div>
                  <div className="sev-bar" style={{ height: 6 }}>
                    <span style={{ flexGrow: c.implemented, background: 'var(--ok)' }} />
                    <span style={{ flexGrow: Math.max(0, c.total - c.implemented), background: 'transparent' }} />
                  </div>
                  {c.fail ? <div className="hero-s">{c.fail} automated check{c.fail === 1 ? '' : 's'} failing</div> : null}
                </div>
              ))}
            </Panel>
            <Panel title="Needs attention" icon={ICONS.bolt}>
              {data.attention.length ? (
                data.attention.map((a) => (
                  <div key={a.ref} className="note">
                    <div className="row-kv" style={{ border: 0, padding: 0, alignItems: 'flex-start' }}>
                      <span className="k" style={{ whiteSpace: 'normal', fontWeight: 600 }}>
                        {a.ref} {a.title}
                      </span>
                      <Tag tone={a.auto_status === 'fail' ? 'bad' : 'warn'}>{a.auto_status === 'fail' ? 'Fail' : 'Warn'}</Tag>
                    </div>
                    {a.detail ? <div className="prose muted" style={{ fontSize: 13, marginTop: 4 }}>{a.detail}</div> : null}
                    <div className="who" style={{ marginTop: 4 }}>
                      {a.status} · {a.owner ?? 'No owner'} · checked {timeAgo(a.evaluated)}
                    </div>
                  </div>
                ))
              ) : (
                <p className="prose muted">All automated checks pass.</p>
              )}
            </Panel>
            </div>
            <p className="updated">{n(s.evidence)} evidence items collected</p>
          </>
        ) : null}
      </div>
    </PullToRefresh>
  )
}
