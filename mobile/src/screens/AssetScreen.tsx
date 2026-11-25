import { useNavigate, useParams } from 'react-router-dom'

import { errorMessage } from '@/api/http'
import { orasec, SEVERITIES } from '@/api/orasec'
import { FindingItem, ICONS, n, Panel, SevBar, SevDot, shortDate, Tag, timeAgo } from '@/components/sec'
import { ErrorState, MetaRow, Screen, SkeletonCards } from '@/components/ui/ds'
import { PullToRefresh } from '@/components/ui/PullToRefresh'
import { useQuery } from '@/hooks/useQuery'

export default function AssetScreen() {
  const params = useParams()
  const key = decodeURIComponent(params['*'] ?? '')
  const navigate = useNavigate()
  const { data: a, error, loading, reload } = useQuery((signal) => orasec.asset(key, signal), [key])

  return (
    <Screen title={a?.name ?? 'Asset'} sub={a ? a.kind : undefined} back>
      <PullToRefresh onRefresh={reload}>
        <div className="stack">
          {error && !a ? <ErrorState onRetry={reload} body={errorMessage(error)} /> : null}
          {loading && !a ? <SkeletonCards n={3} /> : null}
          {a ? (
            <div className="fv">
            <div className="fv-grid">
            <div className="col">
              <section className="card card-pad">
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 10 }}>
                  <Tag tone="mut">{a.kind}</Tag>
                  {a.exposed ? <Tag tone="exp">Internet exposed</Tag> : null}
                  {a.kev ? <Tag tone="kev">{a.kev} known exploited</Tag> : null}
                  {a.overdue ? <Tag tone="bad">{a.overdue} overdue</Tag> : null}
                </div>
                <div className="stat-v">
                  {n(a.total)}
                  <small>open</small>
                </div>
                <div className="mt-2">
                  <SevBar counts={a.sev} height={12} />
                </div>
                <div className="mt-2">
                  {SEVERITIES.map((s, i) => (
                    <button key={s} className="row-kv" style={{ width: '100%' }} disabled={!a.sev[i]} onClick={() => navigate(`/vulns?asset=${encodeURIComponent(a.key)}&severity=${s}`)}>
                      <span className="k">
                        <SevDot s={s} />
                        {s}
                      </span>
                      <span className="v">{n(a.sev[i])}</span>
                    </button>
                  ))}
                </div>
              </section>

              <Panel title="About" icon={ICONS.server}>
                {a.product ? <MetaRow k="Product" v={a.product} mono={false} /> : null}
                {a.where ? <MetaRow k="Runs on" v={a.where} mono={false} /> : null}
                <MetaRow k="Criticality" v={`${a.criticality} of 5`} />
                {a.oldest_days !== null ? <MetaRow k="Oldest open" v={`${a.oldest_days} day${a.oldest_days === 1 ? "" : "s"}`} /> : null}
                {a.inventory ? (
                  <>
                    {a.inventory.hostname ? <MetaRow k="Hostname" v={a.inventory.hostname} /> : null}
                    {a.inventory.ip ? <MetaRow k="IP" v={a.inventory.ip} /> : null}
                    {a.inventory.os ? <MetaRow k="OS" v={a.inventory.os} mono={false} /> : null}
                    {a.inventory.vendor || a.inventory.model ? <MetaRow k="Hardware" v={`${a.inventory.vendor} ${a.inventory.model}`.trim()} mono={false} /> : null}
                    <MetaRow k="Owner" v={a.inventory.owner ?? 'Not set'} mono={false} />
                    <MetaRow k="Last seen" v={timeAgo(a.inventory.last_seen)} mono={false} />
                    {a.inventory.last_scanned ? <MetaRow k="Last scanned" v={shortDate(a.inventory.last_scanned)} /> : null}
                  </>
                ) : null}
              </Panel>

            </div>
            <div className="col">
              <Panel title="Fix first" icon={ICONS.bug} more={`All ${n(a.total)}`} onMore={() => navigate(`/vulns?asset=${encodeURIComponent(a.key)}`)} flush>
                <div className="list flush" style={{ border: 0 }}>
                  {a.top_findings.map((f) => (
                    <FindingItem key={f.id} f={f} />
                  ))}
                </div>
              </Panel>
            </div>
            </div>
            </div>
          ) : null}
        </div>
      </PullToRefresh>
    </Screen>
  )
}
