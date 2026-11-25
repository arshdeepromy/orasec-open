import { errorMessage } from '@/api/http'
import { orasec } from '@/api/orasec'
import { FindingItem, Stat } from '@/components/sec'
import { ErrorState, Screen, SkeletonRows, StateBlock } from '@/components/ui/ds'
import { PullToRefresh } from '@/components/ui/PullToRefresh'
import { useQuery } from '@/hooks/useQuery'

/** What needs you: findings assigned to you, and everything past its fix-by date. */
export default function MyWorkScreen() {
  const { data, error, loading, reload } = useQuery((signal) => orasec.myWork(signal), [])
  return (
    <Screen title="My work" back>
      <PullToRefresh onRefresh={reload}>
        <div className="stack">
          {error && !data ? <ErrorState onRetry={reload} body={errorMessage(error)} /> : null}
          {loading && !data ? <SkeletonRows rows={5} av={false} /> : null}
          {data ? (
            <>
              <div className="stat-grid g3">
                <Stat label="Assigned to me" value={data.counts.mine} />
                <Stat label="Overdue" value={data.counts.overdue} tone={data.counts.overdue ? 'alert' : 'ok'} />
                <Stat label="Due in 7 days" value={data.counts.due7} />
              </div>
              {data.results.length ? (
                <div className="list tgrid">
                  {data.results.map((f) => (
                    <FindingItem key={f.id} f={f} />
                  ))}
                </div>
              ) : (
                <StateBlock title="You're all caught up" body="Nothing is assigned to you and nothing is past its fix-by date." />
              )}
            </>
          ) : null}
        </div>
      </PullToRefresh>
    </Screen>
  )
}
