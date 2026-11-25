import { useNavigate } from 'react-router-dom'

import { errorMessage } from '@/api/http'
import { orasec } from '@/api/orasec'
import { n, Panel, SevBar, SevLegend, Tag, ICONS } from '@/components/sec'
import { ErrorState, Screen, SkeletonCards, StateBlock } from '@/components/ui/ds'
import { PullToRefresh } from '@/components/ui/PullToRefresh'
import { useQuery } from '@/hooks/useQuery'

const CAT_HINT: Record<string, string> = {
  SAST: 'Semgrep',
  Secrets: 'Gitleaks',
  Dependencies: 'Trivy deps & IaC',
  Containers: 'Trivy images',
  GitHub: 'Dependabot & code scanning',
}

/** Code vulnerabilities per product: what is open by scanner type, and how many have been fixed. */
export default function CodeScreen() {
  const navigate = useNavigate()
  const { data, error, loading, reload } = useQuery((signal) => orasec.code(signal), [])
  return (
    <Screen title="Code" sub="Vulnerabilities by product" back>
      <PullToRefresh onRefresh={reload}>
        <div className="stack">
          {error && !data ? <ErrorState onRetry={reload} body={errorMessage(error)} /> : null}
          {loading && !data ? <SkeletonCards n={3} /> : null}
          {data && !data.products.length ? <StateBlock title="No code scans yet" body="Connect GitHub in OraSec (Automation → Connectors) to scan your repositories." /> : null}
          <div className="panel-grid stack">
          {data?.products.map((p) => (
            <Panel key={p.product} title={p.product} icon={ICONS.code} more="Open" onMore={() => navigate(`/vulns?product=${encodeURIComponent(p.product)}`)}>
              <div className="row-kv" style={{ borderBottom: 0, paddingTop: 0 }}>
                <span className="k">
                  <span className="stat-v">{n(p.open)}</span>
                  <span style={{ color: 'var(--muted)', fontSize: 13 }}>open</span>
                </span>
                <span>{p.fixed_pct !== null ? <Tag tone={p.fixed_pct > 0 ? 'ok' : 'mut'}>{p.fixed_pct}% fixed</Tag> : null}</span>
              </div>
              <SevBar counts={p.sev} height={10} />
              <div className="mt-2">
                {data.categories.map((c, i) => (
                  <div key={c} className="row-kv">
                    <span className="k">
                      {c}
                      <span style={{ color: 'var(--muted)', fontSize: 12 }}>{CAT_HINT[c]}</span>
                    </span>
                    <span className={`v${p.cats[i] ? '' : ' muted'}`}>{n(p.cats[i])}</span>
                  </div>
                ))}
                <div className="row-kv">
                  <span className="k">Resolved</span>
                  <span className="v">
                    {n(p.resolved)} <span style={{ color: 'var(--muted)', fontWeight: 500 }}>({n(p.resolved30)} in 30 d)</span>
                  </span>
                </div>
              </div>
            </Panel>
          ))}
          </div>
          {data?.products.length ? <SevLegend /> : null}
        </div>
      </PullToRefresh>
    </Screen>
  )
}
