import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'

import { errorMessage } from '@/api/http'
import { orasec } from '@/api/orasec'
import { n, SevBar, SevLegend, Tag } from '@/components/sec'
import { Chips, ErrorState, Screen, SkeletonRows, StateBlock } from '@/components/ui/ds'
import { PullToRefresh } from '@/components/ui/PullToRefresh'
import { useQuery } from '@/hooks/useQuery'

/** Every scanned asset (hosts, containers, code, cloud, network), riskiest first. */
export default function AssetsScreen() {
  const navigate = useNavigate()
  const { data, error, loading, reload } = useQuery((signal) => orasec.assets('', signal), [])
  const [q, setQ] = useState('')
  const [kind, setKind] = useState('all')

  const kinds = useMemo(() => {
    const counts = new Map<string, number>()
    for (const a of data?.results ?? []) counts.set(a.kind, (counts.get(a.kind) ?? 0) + 1)
    return [{ value: 'all', label: 'All', count: data?.results.length }, ...[...counts.entries()].map(([k, c]) => ({ value: k, label: k, count: c }))]
  }, [data])

  const rows = (data?.results ?? []).filter(
    (a) => (kind === 'all' || a.kind === kind) && (!q || `${a.name} ${a.product ?? ''} ${a.where ?? ''}`.toLowerCase().includes(q.toLowerCase())),
  )

  return (
    <Screen title="Assets" sub={data ? `${data.total} with open findings` : undefined} back>
      <PullToRefresh onRefresh={reload}>
        <div className="stack">
          <input className="input" type="search" placeholder="Search assets…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search assets" />
          <div className="chip-scroll">
            <Chips options={kinds} value={kind} onChange={setKind} />
          </div>
          {error && !data ? <ErrorState onRetry={reload} body={errorMessage(error)} /> : null}
          {loading && !data ? <SkeletonRows rows={6} av={false} /> : null}
          {data && !rows.length ? <StateBlock title="No assets match" body="Try another search or type." /> : null}
          {rows.length ? (
            <div className="list tgrid">
              {rows.map((a) => (
                <button key={a.key} className="li asset-li" onClick={() => navigate(`/assets/${encodeURIComponent(a.key)}`)}>
                  <div className="body">
                    <div className="t">
                      {a.name}
                      {a.exposed ? <Tag tone="exp">Internet</Tag> : null}
                    </div>
                    <div className="s">
                      {a.kind}
                      {a.where ? ` on ${a.where}` : ''}
                      {a.product ? ` · ${a.product}` : ''}
                    </div>
                    <SevBar counts={a.sev} />
                    <div className="meta">
                      <span className="hero-s" style={{ margin: 0 }}>{n(a.total)} open</span>
                      {a.sev[0] ? <Tag tone="bad">{n(a.sev[0])} critical</Tag> : null}
                      {a.kev ? <Tag tone="kev">{a.kev} KEV</Tag> : null}
                      {a.epss ? <Tag tone="epss">{a.epss} EPSS</Tag> : null}
                      {a.overdue ? <Tag tone="bad">{a.overdue} overdue</Tag> : null}
                    </div>
                  </div>
                </button>
              ))}
            </div>
          ) : null}
          {rows.length ? <SevLegend /> : null}
        </div>
      </PullToRefresh>
    </Screen>
  )
}
