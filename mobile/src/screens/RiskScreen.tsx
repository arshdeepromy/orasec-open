import { useParams } from 'react-router-dom'

import { errorMessage } from '@/api/http'
import { orasec } from '@/api/orasec'
import { FindingItem, ICONS, Panel, shortDate, Tag } from '@/components/sec'
import { ErrorState, MetaRow, Screen, SkeletonCards } from '@/components/ui/ds'
import { webAppUrl } from '@/config/serverConfig'
import { isDemoSession } from '@/demo/session'
import { useQuery } from '@/hooks/useQuery'
import { openExternalUrl } from '@/native/browser'

export default function RiskScreen() {
  const { id } = useParams()
  const rid = Number(id)
  const { data: r, error, loading, reload } = useQuery((signal) => orasec.risk(rid, signal), [rid])
  const demo = isDemoSession()
  const side = r ? (
          <>
            <Panel title="Assessment" icon={ICONS.scale}>
              <MetaRow k="Likelihood × impact" v={`${r.likelihood} × ${r.impact} = ${r.score}`} />
              <MetaRow k="After treatment" v={r.residual ?? '—'} />
              <MetaRow k="Treatment" v={r.treatment} mono={false} />
              <MetaRow k="Owner" v={r.owner ?? 'Not set'} mono={false} />
              <MetaRow k="Review by" v={shortDate(r.review)} />
              {r.product ? <MetaRow k="Product" v={r.product} mono={false} /> : null}
            </Panel>
            {r.controls.length ? (
              <Panel title="ISO 27001 controls" icon={ICONS.scale}>
                {r.controls.map((c) => (
                  <MetaRow key={c.ref} k={c.ref} v={c.title} mono={false} />
                ))}
              </Panel>
            ) : null}
            {demo ? null : (
              <button className="btn btn-ghost" onClick={() => void openExternalUrl(webAppUrl(`/orasec/risks/${r.id}/`))}>
                Edit on the web
              </button>
            )}
          </>
  ) : null
  return (
    <Screen title={r?.ref ?? 'Risk'} back>
      {error && !r ? <ErrorState onRetry={reload} body={errorMessage(error)} /> : null}
      {loading && !r ? <SkeletonCards n={3} /> : null}
      {r ? (
        <div className="fv">
        <div className="fv-grid">
        <div className="col">
          <section className="card card-pad">
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 10 }}>
              <Tag tone={r.score >= 15 ? 'bad' : r.score >= 8 ? 'warn' : 'ok'}>Score {r.score}</Tag>
              <Tag tone="mut">{r.status_label}</Tag>
              {r.review_overdue ? <Tag tone="bad">Review overdue</Tag> : null}
            </div>
            <h1 style={{ fontSize: 17, fontWeight: 700, lineHeight: 1.35 }}>{r.title}</h1>
          </section>
          <div className="fv-1only stack">{side}</div>
          {r.description ? (
            <Panel title="Description" icon={ICONS.info}>
              <p className="prose">{r.description}</p>
            </Panel>
          ) : null}
          {r.threat || r.vulnerability ? (
            <Panel title="Threat and weakness" icon={ICONS.skull}>
              {r.threat ? <p className="prose">{r.threat}</p> : null}
              {r.vulnerability ? <p className="prose mt">{r.vulnerability}</p> : null}
            </Panel>
          ) : null}
          {r.treatment_plan ? (
            <Panel title="Treatment plan" icon={ICONS.shield}>
              <p className="prose">{r.treatment_plan}</p>
            </Panel>
          ) : null}
          {r.findings.length ? (
            <Panel title="Linked vulnerabilities" icon={ICONS.bug} flush>
              <div className="list flush" style={{ border: 0 }}>
                {r.findings.map((f) => (
                  <FindingItem key={f.id} f={f} />
                ))}
              </div>
            </Panel>
          ) : null}
        </div>
        <div className="col side fv-2only">{side}</div>
        </div>
        </div>
      ) : null}
    </Screen>
  )
}
