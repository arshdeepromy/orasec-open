import { useCallback, useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'

import { errorMessage } from '@/api/http'
import { orasec, type FindingDetail, type FindingFilters, type FindingRow, type Severity, SEVERITIES } from '@/api/orasec'
import { FindingItem, n } from '@/components/sec'
import { Chips, ErrorState, I, Icon, Screen, SkeletonRows, StateBlock } from '@/components/ui/ds'
import { PullToRefresh } from '@/components/ui/PullToRefresh'
import { useLayout } from '@/hooks/useLayout'
import { FindingView } from '@/screens/FindingScreen'

type Quick = 'open' | 'critical' | 'kev' | 'epss' | 'overdue' | 'mine' | 'closed'

const QUICK: Array<{ value: Quick; label: string }> = [
  { value: 'open', label: 'All open' },
  { value: 'critical', label: 'Critical & High' },
  { value: 'kev', label: 'Known exploited' },
  { value: 'epss', label: 'Likely exploited' },
  { value: 'overdue', label: 'Overdue' },
  { value: 'mine', label: 'Assigned to me' },
  { value: 'closed', label: 'Resolved' },
]

function filtersFrom(quick: Quick, params: URLSearchParams, q: string): FindingFilters {
  const sev = params.get('severity')
  const f: FindingFilters = {
    q: q || undefined,
    asset: params.get('asset') ?? undefined,
    product: params.get('product') ?? undefined,
    sort: params.get('sort') === 'newest' ? 'newest' : 'priority',
    severity: sev ? (sev.split(',').filter((s) => SEVERITIES.includes(s as Severity)) as Severity[]) : undefined,
  }
  if (quick === 'critical') f.severity = ['Critical', 'High']
  if (quick === 'kev') f.kev = true
  if (quick === 'epss') f.epss = true
  if (quick === 'overdue') f.overdue = true
  if (quick === 'mine') f.mine = true
  if (quick === 'closed') f.status = 'closed'
  return f
}

function quickFrom(params: URLSearchParams): Quick {
  if (params.get('kev') === '1') return 'kev'
  if (params.get('epss') === '1') return 'epss'
  if (params.get('overdue') === '1') return 'overdue'
  if (params.get('mine') === '1') return 'mine'
  if (params.get('status') === 'closed') return 'closed'
  return 'open'
}

export default function VulnsScreen() {
  const [params, setParams] = useSearchParams()
  const [quick, setQuick] = useState<Quick>(() => quickFrom(params))
  const [search, setSearch] = useState(params.get('q') ?? '')
  const [q, setQ] = useState(params.get('q') ?? '')
  const [rows, setRows] = useState<FindingRow[]>([])
  const [total, setTotal] = useState<number | null>(null)
  const [next, setNext] = useState<number | null>(null)
  const [loading, setLoading] = useState(true)
  const [more, setMore] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const [reloadKey, setReloadKey] = useState(0)

  const { split } = useLayout()
  const selected = Number(params.get('id')) || null
  // The selection lives in ?id= so it is not part of the filters (selecting a row must not reload the list).
  const filterKey = useMemo(() => {
    const p = new URLSearchParams(params)
    p.delete('id')
    return p.toString()
  }, [params])
  const filterParams = useMemo(() => new URLSearchParams(filterKey), [filterKey])
  const filters = useMemo(() => filtersFrom(quick, filterParams, q), [quick, filterParams, q])

  const select = useCallback(
    (id: number | null, replace = false) => {
      const p = new URLSearchParams(params)
      if (id) p.set('id', String(id))
      else p.delete('id')
      setParams(p, { replace })
    },
    [params, setParams],
  )

  // Split view: open the first finding when nothing is selected yet.
  useEffect(() => {
    if (split && !selected && rows.length && !loading) select(rows[0].id, true)
  }, [split, selected, rows, loading, select])

  const onChanged = useCallback((d: FindingDetail) => {
    setRows((rs) => rs.map((r) => (r.id === d.id ? { ...r, active: d.active, mitigated: d.mitigated, overdue: d.overdue } : r)))
  }, [])
  const scoped = params.get('asset') || params.get('product') || params.get('severity')

  // debounce typing
  useEffect(() => {
    const t = window.setTimeout(() => setQ(search.trim()), 350)
    return () => window.clearTimeout(t)
  }, [search])

  useEffect(() => {
    const controller = new AbortController()
    setLoading(true)
    setError(null)
    orasec
      .findings(filters, 0, controller.signal)
      .then((page) => {
        setRows(page.results)
        setTotal(page.total)
        setNext(page.next)
      })
      .catch((err) => {
        if (!controller.signal.aborted) setError(err)
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false)
      })
    return () => controller.abort()
  }, [filters, reloadKey])

  const loadMore = async () => {
    if (next === null || more) return
    setMore(true)
    try {
      const page = await orasec.findings(filters, next)
      setRows((r) => [...r, ...page.results])
      setNext(page.next)
    } catch (err) {
      setError(err)
    } finally {
      setMore(false)
    }
  }

  const clearScope = () => {
    const p = new URLSearchParams()
    setParams(p, { replace: true })
  }

  const sub = total !== null ? `${n(total)} ${quick === 'closed' ? 'resolved' : 'open'}` : undefined
  const changeQuick = (v: Quick) => {
    setQuick(v)
    if (selected) select(null, true)
  }

  const listBody = (
    <>
          <div className="searchrow">
            <input
              className="input"
              type="search"
              placeholder="Search CVE, package, asset…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              aria-label="Search vulnerabilities"
              data-testid="vuln-search"
            />
          </div>
          <div className="chip-scroll">
            <Chips options={QUICK} value={quick} onChange={(v) => changeQuick(v as Quick)} />
          </div>
          {scoped ? (
            <div className="callout">
              <Icon d={I.filter} size={18} />
              <span style={{ flex: 1 }}>
                Showing {params.get('asset') ? `asset ${params.get('asset')}` : params.get('product') ? `product ${params.get('product')}` : `${params.get('severity')} only`}
              </span>
              <button className="panel-more" onClick={clearScope}>
                Clear
              </button>
            </div>
          ) : null}

          {error && !rows.length ? <ErrorState onRetry={() => setReloadKey((k) => k + 1)} body={errorMessage(error)} /> : null}
          {loading && !rows.length ? <SkeletonRows rows={7} av={false} /> : null}
          {!loading && !error && rows.length === 0 ? (
            <StateBlock title={quick === 'closed' ? 'Nothing resolved here yet' : 'Nothing to fix here'} body="No vulnerabilities match these filters." />
          ) : null}
          {rows.length ? (
            <div className={`list${split ? '' : ' tgrid'}`} style={{ opacity: loading ? 0.6 : 1 }}>
              {rows.map((f) => (
                <FindingItem key={f.id} f={f} onSelect={split ? (id) => select(id) : undefined} selected={split && f.id === selected} />
              ))}
            </div>
          ) : null}
          {next !== null ? (
            <button className="btn btn-ghost" onClick={() => void loadMore()} disabled={more} data-testid="load-more">
              {more ? 'Loading…' : `Show more (${n((total ?? 0) - rows.length)} left)`}
            </button>
          ) : null}
    </>
  )

  if (split) {
    return (
      <Screen
        title="Vulnerabilities"
        sub={sub}
        large
        padded={false}
        className="split-screen"
        actions={
          <button className="nav-btn" aria-label="Refresh" onClick={() => setReloadKey((k) => k + 1)}>
            <Icon d={I.refresh} />
          </button>
        }
      >
        <div className="split" data-testid="vulns-split">
          <div className="split-list">{listBody}</div>
          <div className="split-detail">
            {selected ? (
              <FindingView key={selected} id={selected} embedded onChanged={onChanged} />
            ) : (
              <div className="split-empty">{loading ? 'Loading…' : 'Choose a vulnerability to see the details.'}</div>
            )}
          </div>
        </div>
      </Screen>
    )
  }

  return (
    <Screen title="Vulnerabilities" sub={sub} large>
      <PullToRefresh onRefresh={() => setReloadKey((k) => k + 1)}>
        <div className="stack">{listBody}</div>
      </PullToRefresh>
    </Screen>
  )
}

