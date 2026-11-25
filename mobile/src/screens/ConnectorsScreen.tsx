import { errorMessage } from '@/api/http'
import { orasec, type PluginRow } from '@/api/orasec'
import { ICONS, n, Panel, Tag, timeAgo } from '@/components/sec'
import { ErrorState, Screen, SkeletonRows } from '@/components/ui/ds'
import { PullToRefresh } from '@/components/ui/PullToRefresh'
import { useQuery } from '@/hooks/useQuery'

/**
 * Health of the data sources that feed OraSec (scanners, firewalls, cloud), the exploit-intelligence feeds, and which
 * plugins the server has switched on. Read only: an administrator turns plugins on or off on the web (Automation, Plugins).
 */
/** Plugins in the server's order, one block per group. */
export function groupPlugins(rows: PluginRow[]): Array<{ name: string; rows: PluginRow[] }> {
  const groups: Array<{ name: string; rows: PluginRow[] }> = []
  for (const row of rows) {
    const last = groups[groups.length - 1]
    if (last && last.name === row.group) last.rows.push(row)
    else groups.push({ name: row.group, rows: [row] })
  }
  return groups
}

export default function ConnectorsScreen() {
  const { data, error, loading, reload } = useQuery((signal) => orasec.connectors(signal), [])
  // Older servers have no plugin list: the panel is simply left out.
  const plugins = useQuery((signal) => orasec.plugins(signal).catch(() => ({ plugins: [] as PluginRow[] })), [])
  const groups = groupPlugins(plugins.data?.plugins ?? [])
  return (
    <Screen title="Data sources" sub={data ? `${data.connectors.filter((c) => c.healthy).length} of ${data.connectors.length} healthy` : undefined} back>
      <PullToRefresh
        onRefresh={() => {
          reload()
          plugins.reload()
        }}
      >
        <div className="stack">
          {error && !data ? <ErrorState onRetry={reload} body={errorMessage(error)} /> : null}
          {loading && !data ? <SkeletonRows rows={6} av={false} /> : null}
          {data ? (
            <>
              <div className="list tgrid">
                {data.connectors.map((c) => (
                  <div key={c.id} className="li" style={{ alignItems: 'flex-start' }}>
                    <div className="body">
                      <div className="t">{c.name}</div>
                      <div className="s">{c.kind}</div>
                      <div className="s">
                        Last success {timeAgo(c.last_success)} · every {c.interval_minutes >= 60 ? `${Math.round(c.interval_minutes / 60)} h` : `${c.interval_minutes} min`}
                      </div>
                      {!c.healthy && c.message ? (
                        <div className="prose muted" style={{ fontSize: 12.5, marginTop: 4, whiteSpace: 'normal' }}>
                          {c.message}
                        </div>
                      ) : null}
                    </div>
                    <div className="end">
                      <Tag tone={!c.enabled ? 'mut' : c.healthy ? 'ok' : c.status === 'error' || c.status === 'fail' ? 'bad' : 'warn'}>
                        {c.plugin_on === false ? 'Plugin off' : !c.enabled ? 'Off' : c.healthy ? 'Healthy' : c.status === 'running' ? 'Running' : c.status === 'never' ? 'Not run' : c.status === 'error' ? 'Error' : 'Late'}
                      </Tag>
                    </div>
                  </div>
                ))}
              </div>
              <Panel title="Threat intelligence" icon={ICONS.shield}>
                {data.feeds.map((f) => (
                  <div key={f.name} className="row-kv">
                    <span className="k">
                      {f.name === 'KEV' ? 'CISA known exploited' : f.name === 'EPSS' ? 'EPSS exploit prediction' : f.name}
                      <span style={{ color: 'var(--muted)', fontSize: 12 }}>{n(f.records)}</span>
                    </span>
                    <Tag tone={f.status === 'ok' ? 'ok' : 'warn'}>{timeAgo(f.last)}</Tag>
                  </div>
                ))}
              </Panel>
              {groups.map((g) => (
                <Panel key={g.name} title={`Plugins · ${g.name}`} icon={ICONS.plug}>
                  {g.rows.map((p) => (
                    <div key={p.key} className="row-kv" data-testid={`plugin-${p.key}`}>
                      <span className="k" style={{ minWidth: 0, whiteSpace: 'normal', overflowWrap: 'anywhere' }}>
                        {p.name}
                      </span>
                      <Tag tone={p.active ? 'ok' : p.on ? 'warn' : 'mut'}>{p.active ? 'On' : p.on ? 'Not set up' : 'Off'}</Tag>
                    </div>
                  ))}
                </Panel>
              ))}
            </>
          ) : null}
        </div>
      </PullToRefresh>
    </Screen>
  )
}
