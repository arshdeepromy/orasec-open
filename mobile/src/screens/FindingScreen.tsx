import { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'

import { errorMessage } from '@/api/http'
import { orasec, type FindingDetail } from '@/api/orasec'
import { ICONS, n, Panel, pct, plainText, SevBadge, shortDate, Tag } from '@/components/sec'
import { ErrorState, I, Icon, MetaRow, Screen, SkeletonCards } from '@/components/ui/ds'
import { Sheet } from '@/components/ui/Sheet'
import { webAppUrl } from '@/config/serverConfig'
import { isDemoSession } from '@/demo/session'
import { useHaptics } from '@/hooks/useHaptics'
import { useQuery } from '@/hooks/useQuery'
import { openExternalUrl } from '@/native/browser'
import { formatDateTime } from '@/utils/format'

type Reason = 'mitigated' | 'false_positive' | 'out_of_scope'
const REASONS: Array<{ value: Reason; label: string; hint: string }> = [
  { value: 'mitigated', label: 'Fixed', hint: 'Patched, upgraded or reconfigured.' },
  { value: 'false_positive', label: 'False positive', hint: 'The scanner was wrong.' },
  { value: 'out_of_scope', label: 'Out of scope', hint: 'Not ours to fix or no longer in use.' },
]

function firstUrl(refs: string | null): string[] {
  if (!refs) return []
  return Array.from(new Set(refs.match(/https?:\/\/[^\s,)\]]+/g) ?? [])).slice(0, 6)
}

/** Full-screen finding (phones, and tablets without room for the split view). */
export default function FindingScreen() {
  const { id } = useParams()
  const [head, setHead] = useState<FindingDetail | null>(null)
  return (
    <Screen title={head ? head.severity : 'Vulnerability'} sub={head?.cve ?? undefined} back padded={false}>
      <div className="pad stack" style={{ flex: 1, paddingBottom: 0 }}>
        <FindingView id={Number(id)} onLoaded={setHead} />
      </div>
    </Screen>
  )
}

/**
 * One finding: summary, priority, details, notes and the actions (assign, note, resolve).
 * `embedded` = shown in the right-hand pane of the Vulnerabilities split view on tablets.
 */
export function FindingView({ id: fid, embedded = false, onLoaded, onChanged }: {
  id: number
  embedded?: boolean
  onLoaded?: (f: FindingDetail) => void
  onChanged?: (f: FindingDetail) => void
}) {
  const navigate = useNavigate()
  const haptics = useHaptics()
  const { data, error, loading, reload, setData } = useQuery((signal) => orasec.finding(fid, signal), [fid])
  const [sheet, setSheet] = useState<'none' | 'note' | 'close'>('none')
  const [text, setText] = useState('')
  const [reason, setReason] = useState<Reason>('mitigated')
  const [busy, setBusy] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)
  const [toast, setToast] = useState<string | null>(null)
  const demo = isDemoSession()

  useEffect(() => {
    if (data) onLoaded?.(data)
  }, [data, onLoaded])

  const run = async (fn: () => Promise<FindingDetail>, done: string) => {
    setBusy(true)
    setActionError(null)
    try {
      const updated = await fn()
      setData(updated)
      onChanged?.(updated)
      setSheet('none')
      setText('')
      void haptics.medium()
      setToast(done)
      window.setTimeout(() => setToast(null), 2500)
    } catch (err) {
      setActionError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const f = data && data.id === fid ? data : null
  const sidePanels = f ? (
    <>
      <Panel title="Priority" icon={ICONS.stopwatch}>
        <MetaRow k="Band" v={f.band ?? '—'} mono={false} />
        <MetaRow k="Score" v={f.score ?? '—'} />
        <MetaRow k="Fix by" v={f.due ? shortDate(f.due) : '—'} />
        {f.sla_basis ? <MetaRow k="Why" v={f.sla_basis} mono={false} /> : null}
        <MetaRow k="Detected" v={shortDate(f.date)} />
        <MetaRow k="Assigned to" v={f.assignee ?? 'Nobody'} mono={false} />
        {f.mitigated_at ? <MetaRow k="Resolved" v={`${formatDateTime(f.mitigated_at)}${f.mitigated_by ? ` by ${f.mitigated_by}` : ''}`} mono={false} /> : null}
      </Panel>

      <Panel title="Details" icon={ICONS.bug}>
        {f.component ? <MetaRow k="Package" v={`${f.component}${f.component_version ? ` ${f.component_version}` : ''}`} /> : null}
        {f.fix_version ? <MetaRow k="Fixed in" v={f.fix_version} /> : null}
        {f.cve ? <MetaRow k="CVE" v={f.cve} /> : null}
        {f.cwe ? <MetaRow k="CWE" v={`CWE-${f.cwe}`} /> : null}
        {f.cvss ? <MetaRow k="CVSS v3" v={f.cvss} /> : null}
        {f.epss_percentile !== null ? <MetaRow k="EPSS percentile" v={pct(f.epss_percentile, 1)} /> : null}
        {f.file_path ? <MetaRow k="File" v={`${f.file_path}${f.line ? `:${f.line}` : ''}`} /> : null}
        {f.scanner ? <MetaRow k="Found by" v={f.scanner} mono={false} /> : null}
      </Panel>
    </>
  ) : null
  const webButton =
    f && !demo ? (
      <button className="btn btn-ghost" onClick={() => void openExternalUrl(webAppUrl(f.web_url))}>
        Open in OraSec web
      </button>
    ) : null

  return (
    <div className="fv" data-testid={embedded ? 'finding-pane' : 'finding-view'}>
      {error && !f ? <ErrorState onRetry={reload} body={errorMessage(error)} /> : null}
      {loading && !f ? <SkeletonCards n={3} /> : null}
      {f ? (
        <>
          <div className="fv-grid">
            <div className="col">
              <section className="card card-pad">
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 10 }}>
                  <SevBadge s={f.severity} />
                  {f.kev ? <Tag tone="kev">Known exploited (CISA KEV)</Tag> : null}
                  {f.ransomware ? <Tag tone="bad">Used in ransomware</Tag> : null}
                  {f.epss !== null ? <Tag tone={f.epss >= 0.1 ? 'epss' : 'mut'}>EPSS {pct(f.epss, 1)}</Tag> : null}
                  {f.overdue ? <Tag tone="bad">Overdue</Tag> : null}
                  {!f.active ? <Tag tone="ok">{f.mitigated ? 'Resolved' : 'Closed'}</Tag> : null}
                </div>
                <h1 style={{ fontSize: embedded ? 19 : 17, fontWeight: 700, lineHeight: 1.35 }}>{f.title}</h1>
                <p className="hero-s" style={{ marginTop: 6 }}>
                  {f.asset}
                  {f.product ? ` · ${f.product}` : ''}
                </p>
              </section>

              <div className="fv-1only stack">{sidePanels}</div>

              {f.description ? (
                <Panel title="Description" icon={ICONS.info}>
                  <p className="prose">{plainText(f.description)}</p>
                </Panel>
              ) : null}
              {f.mitigation ? (
                <Panel title="How to fix" icon={ICONS.shield}>
                  <p className="prose">{plainText(f.mitigation, 2000)}</p>
                </Panel>
              ) : null}
              {firstUrl(f.references).length ? (
                <Panel title="References" icon={ICONS.link}>
                  {firstUrl(f.references).map((u) => (
                    <button key={u} className="row-kv" style={{ width: '100%' }} onClick={() => void openExternalUrl(u)}>
                      <span className="k mono-s" style={{ color: 'var(--accent-fg)' }}>
                        {u.replace(/^https?:\/\//, '')}
                      </span>
                    </button>
                  ))}
                </Panel>
              ) : null}

              <Panel title={`Notes (${n(f.notes.length)})`} icon={I.edit}>
                {f.notes.length ? (
                  f.notes.map((note) => (
                    <div key={note.id} className="note">
                      <div className="who">
                        {note.author} · {formatDateTime(note.date)}
                      </div>
                      <div className="prose">{note.text}</div>
                    </div>
                  ))
                ) : (
                  <p className="prose muted">No notes yet.</p>
                )}
              </Panel>
              {webButton ? <div className="fv-1only stack">{webButton}</div> : null}
            </div>

            <div className="col side fv-2only">
              {sidePanels}
              {webButton}
            </div>
          </div>
          <div style={{ height: embedded ? 24 : 70, flexShrink: 0 }} />

          <div className="action-bar">
            {f.active ? (
              <>
                <button className="btn btn-ghost" disabled={busy} onClick={() => void run(() => orasec.assign(fid, f.assigned_to_me), f.assigned_to_me ? 'Unassigned' : 'Assigned to you')} data-testid="assign">
                  {f.assigned_to_me ? 'Unassign' : 'Assign to me'}
                </button>
                <button className="btn btn-ghost" onClick={() => setSheet('note')} data-testid="add-note">
                  Note
                </button>
                <button className="btn btn-primary" onClick={() => setSheet('close')} data-testid="close-finding">
                  Resolve
                </button>
              </>
            ) : (
              <>
                <button className="btn btn-ghost" onClick={() => setSheet('note')}>
                  Add note
                </button>
                {embedded ? null : (
                  <button className="btn btn-ghost" onClick={() => navigate(-1)}>
                    Done
                  </button>
                )}
              </>
            )}
          </div>

          <Sheet
            open={sheet === 'note'}
            title="Add a note"
            onClose={() => setSheet('none')}
            footer={
              <button className="btn btn-primary" disabled={busy || !text.trim()} onClick={() => void run(() => orasec.addNote(fid, text.trim()), 'Note added')}>
                {busy ? 'Saving…' : 'Add note'}
              </button>
            }
          >
            <textarea className="textarea" data-autofocus rows={5} value={text} onChange={(e) => setText(e.target.value)} placeholder="What did you check or change?" />
            {actionError ? <p className="field err-msg mt">{actionError}</p> : null}
          </Sheet>

          <Sheet
            open={sheet === 'close'}
            title="Resolve vulnerability"
            onClose={() => setSheet('none')}
            footer={
              <button className="btn btn-primary" disabled={busy || !text.trim()} onClick={() => void run(() => orasec.closeFinding(fid, reason, text.trim()), 'Resolved')} data-testid="confirm-close">
                {busy ? 'Saving…' : 'Resolve'}
              </button>
            }
          >
            <div className="stack" style={{ gap: 8 }}>
              {REASONS.map((r) => (
                <button key={r.value} className={`card card-pad${reason === r.value ? ' selected-reason' : ''}`} style={{ textAlign: 'left', outline: reason === r.value ? '2px solid var(--accent)' : undefined }} onClick={() => setReason(r.value)}>
                  <div style={{ fontWeight: 600 }}>{r.label}</div>
                  <div className="hero-s">{r.hint}</div>
                </button>
              ))}
              <label className="field" style={{ marginTop: 6, marginBottom: 0 }}>
                <span style={{ fontSize: 13, fontWeight: 600 }}>Note (required)</span>
                <textarea className="textarea" rows={3} value={text} onChange={(e) => setText(e.target.value)} placeholder="e.g. Upgraded openssl to 3.5.4 on 16 Nov" />
              </label>
              <p className="hero-s">If the next scan still finds it, OraSec reopens it automatically.</p>
              {actionError ? <p className="field err-msg">{actionError}</p> : null}
            </div>
          </Sheet>

          {toast ? (
            <div className="toast show" role="status">
              <Icon d={I.check} size={18} /> {toast}
            </div>
          ) : null}
        </>
      ) : null}
    </div>
  )
}

