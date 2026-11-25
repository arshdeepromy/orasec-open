/**
 * OraSheet — Ora's chat as a full-screen sheet (mobile port of the web panel; same API and payloads).
 *
 * Views: chat · history · notes. Chat: first-run notice, typing state (orb "working"), answers with
 * steps, finding/risk rows (tap → the matching app screen), "Take me there" (the app screen, or "Open on
 * web" when the page only exists on the web), proposal cards (Confirm / Cancel — nothing changes before
 * Confirm), quick replies, suggestions and 👍/👎.
 * Android back: a sub-view goes back to the chat; the chat closes the sheet.
 */
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'

import { ApiError } from '@/api/http'
import { webAppUrl } from '@/config/serverConfig'
import { useBackButtonClose } from '@/hooks/useBackButtonClose'
import { openExternalUrl } from '@/native/browser'
import OraOrb from './OraOrb'
import { oraApi } from './oraApi'
import type { OraAction, OraItem, OraMessage, OraMood, OraProposal, OraStatus } from './oraApi'
import { ORA_ICONS, OraIcon, OraPortal, Z_SHEET } from './oraUi'

type View = 'chat' | 'history' | 'notes'
const STARTERS = ['What should we fix first?', 'How is our security posture?', 'Which known-exploited vulnerabilities affect us?', 'Any overdue findings?']
const CID_KEY = 'ora.cid.v1'

/** Web paths in answers → app screens (anything else opens on the web). */
export function mobilePathFor(path: string | null | undefined, appPath?: string | null): string | null {
  if (appPath) return appPath
  if (!path) return null
  let m = path.match(/^\/finding\/(\d+)/)
  if (m) return `/vulns/${m[1]}`
  m = path.match(/^\/orasec\/risks\/(\d+)\//)
  if (m) return `/risks/${m[1]}`
  const map: Record<string, string> = {
    '/dashboard': '/', '/orasec/command-center/': '/', '/orasec/vulnerabilities/': '/vulns', '/finding/open': '/vulns',
    '/orasec/my-work/': '/my-work', '/orasec/remediation/': '/my-work', '/orasec/inventory/': '/assets',
    '/orasec/attacks/': '/attacks', '/orasec/code/': '/code', '/orasec/connectors/': '/connectors',
    '/orasec/risks/': '/governance', '/orasec/compliance/': '/governance', '/orasec/risk-acceptances/': '/governance',
  }
  return map[path.split('?')[0]] ?? null
}

function openOnWeb(path: string) {
  void openExternalUrl(webAppUrl(path))
}

function ago(iso?: string) {
  if (!iso) return ''
  const d = new Date(iso)
  const s = (Date.now() - d.getTime()) / 1000
  if (s < 60) return 'just now'
  if (s < 3600) return `${Math.floor(s / 60)} min ago`
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`
  return d.toLocaleDateString(undefined, { day: 'numeric', month: 'short' })
}

function errText(e: unknown) {
  return e instanceof ApiError ? e.message : 'Ora is having a moment — try again shortly.'
}

interface Props {
  status: OraStatus | null
  mood: OraMood
  setMood: (m: OraMood, holdMs?: number) => void
  onClose: () => void
  onStatus: (s: OraStatus) => void
}

export default function OraSheet({ status, mood, setMood, onClose, onStatus }: Props) {
  const navigate = useNavigate()
  const location = useLocation()
  const [view, setView] = useState<View>('chat')
  const [cid, setCid] = useState<number | null>(() => {
    const v = Number(sessionStorage.getItem(CID_KEY))
    return Number.isFinite(v) && v > 0 ? v : null
  })
  const [msgs, setMsgs] = useState<OraMessage[]>([])
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [text, setText] = useState('')
  const bodyRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)

  useBackButtonClose(true, () => (view === 'chat' ? onClose() : setView('chat')))

  useEffect(() => {
    if (!cid) return
    oraApi.conversation(cid).then((c) => setMsgs(c.messages)).catch(() => {
      sessionStorage.removeItem(CID_KEY)
      setCid(null)
    })
    // only on mount
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useLayoutEffect(() => {
    if (view === 'chat' && bodyRef.current) bodyRef.current.scrollTop = bodyRef.current.scrollHeight
  }, [msgs, busy, view])

  const send = useCallback(
    async (raw: string) => {
      const q = raw.trim()
      if (!q || busy) return
      setErr(null)
      setText('')
      setBusy(true)
      setMsgs((m) => [...m, { role: 'user', text: q }])
      setMood('working')
      try {
        const title = document.querySelector('h1')?.textContent?.trim() ?? ''
        const r = await oraApi.chat(q, cid, { path: location.pathname, title })
        setCid(r.conversation_id)
        sessionStorage.setItem(CID_KEY, String(r.conversation_id))
        setMsgs((m) => [...m, r.message])
        const md = r.message.mood
        setMood(md === 'sorry' ? 'sorry' : md === 'listening' ? 'listening' : 'happy', 3500)
      } catch (e) {
        setErr(errText(e))
        setMood(e instanceof ApiError && e.status === 429 ? 'sleeping' : 'sorry', 4000)
      } finally {
        setBusy(false)
      }
    },
    [busy, cid, location.pathname, setMood],
  )

  const newChat = () => {
    sessionStorage.removeItem(CID_KEY)
    setCid(null)
    setMsgs([])
    setErr(null)
    setView('chat')
  }

  const go = (a: OraAction) => {
    const app = mobilePathFor(a.path, a.app_path)
    if (app) {
      onClose()
      navigate(app)
    } else if (a.path) openOnWeb(a.path)
  }
  const openItem = (it: OraItem) => {
    const app = mobilePathFor(it.path)
    if (app) {
      onClose()
      navigate(app)
    } else if (it.path) openOnWeb(it.path)
  }

  const updateMsg = (idx: number, patch: Partial<OraMessage>) => setMsgs((m) => m.map((x, i) => (i === idx ? { ...x, ...patch } : x)))

  const st = status
  return (
    <OraPortal>
      <div className="ora-sheet" role="dialog" aria-modal="true" aria-label="Ora assistant" style={{ zIndex: Z_SHEET }} data-testid="ora-sheet">
        <header className="ora-sheet-head">
          {view !== 'chat' ? (
            <button type="button" className="ora-ib" aria-label="Back to the chat" onClick={() => setView('chat')}>
              <OraIcon d={ORA_ICONS.back} />
            </button>
          ) : null}
          <OraOrb mood={mood} size={38} title="Ora" />
          <div className="ora-sheet-title">
            <h2>{view === 'history' ? 'Chats' : view === 'notes' ? 'Notes' : 'Ora'}</h2>
            <p aria-live="polite">{busy ? 'Thinking…' : view === 'history' ? 'Your recent chats' : view === 'notes' ? 'What I remember' : 'Your OraSec assistant'}</p>
          </div>
          <button type="button" className="ora-ib" aria-label="New chat" onClick={newChat}>
            <OraIcon d={ORA_ICONS.plus} />
          </button>
          {view === 'chat' ? (
            <button type="button" className="ora-ib" aria-label="Chat history" onClick={() => setView('history')}>
              <OraIcon d={ORA_ICONS.clock} />
            </button>
          ) : null}
          <button type="button" className="ora-ib" aria-label="Close Ora" onClick={onClose}>
            <OraIcon d={ORA_ICONS.close} />
          </button>
        </header>

        <div className="ora-sheet-body" ref={bodyRef}>
          {view === 'history' ? (
            <History onOpen={(id, m) => { setCid(id); sessionStorage.setItem(CID_KEY, String(id)); setMsgs(m); setView('chat') }} onDeleted={(id) => { if (id === cid) newChat() }} />
          ) : view === 'notes' ? (
            <Notes notice={st?.memory_notice} />
          ) : (
            <>
              {st && !st.available ? (
                <div className="ora-err">{st.configured ? 'Ora is resting right now. Please try again a bit later.' : 'Ora isn’t set up yet. A superuser can connect it in Ora settings on the web.'}</div>
              ) : null}
              {st && st.available && !st.notice_ack ? (
                <div className="ora-note" data-testid="ora-first-run">
                  <p>{st.notice}</p>
                  {st.memory_notice ? <p className="ora-muted">{st.memory_notice}</p> : null}
                  <div className="ora-right">
                    <button type="button" className="ora-btn p" onClick={() => { onStatus({ ...st, notice_ack: true }); void oraApi.preference({ notice_ack: true }) }}>
                      Got it
                    </button>
                  </div>
                </div>
              ) : null}
              {st?.available && msgs.length === 0 ? (
                <div className="ora-hello">
                  <OraOrb mood={mood === 'idle' ? 'happy' : mood} size={84} decorative />
                  <h3>Kia ora{st.first_name ? ` ${st.first_name}` : ''}! I’m Ora.</h3>
                  <p>I can prioritise findings, evaluate risk, explain vulnerabilities, find your way around OraSec and prepare changes for you to confirm.</p>
                  <div className="ora-chips center">
                    {STARTERS.map((q) => (
                      <button key={q} type="button" className="ora-chip" onClick={() => void send(q)}>{q}</button>
                    ))}
                  </div>
                </div>
              ) : null}
              {msgs.map((m, i) =>
                m.role === 'user' ? (
                  <div key={i} className="ora-u"><p>{m.text}</p></div>
                ) : (
                  <Answer key={i} m={m} last={i === msgs.length - 1} onSend={send} onGo={go} onItem={openItem}
                    onUpdate={(p) => updateMsg(i, p)} setMood={setMood} />
                ),
              )}
              {busy ? (
                <div className="ora-typing" role="status" aria-label="Ora is typing">
                  <OraOrb mood="working" size={28} decorative />
                  <span className="dots"><i /><i /><i /></span>
                </div>
              ) : null}
              {err ? <div className="ora-err" role="alert">{err}</div> : null}
            </>
          )}
        </div>

        {view === 'chat' ? (
          <footer className="ora-sheet-foot">
            <form className="ora-comp" onSubmit={(e) => { e.preventDefault(); void send(text) }}>
              <textarea
                ref={inputRef}
                rows={1}
                maxLength={2000}
                value={text}
                placeholder="Ask about findings, risks…"
                aria-label="Ask Ora"
                onChange={(e) => {
                  setText(e.target.value)
                  e.target.style.height = 'auto'
                  e.target.style.height = `${Math.min(120, e.target.scrollHeight)}px`
                  if (!busy) setMood(e.target.value.trim() ? 'listening' : 'idle')
                }}
              />
              <button type="submit" className="ora-send" aria-label="Send" disabled={!text.trim() || busy}>
                <OraIcon d={ORA_ICONS.send} />
              </button>
            </form>
            <div className="ora-meta">
              <span>Ora can make mistakes.</span>
              <button type="button" onClick={() => setView('notes')}>Notes</button>
            </div>
          </footer>
        ) : null}
      </div>
    </OraPortal>
  )
}

function Sev({ s }: { s?: string | null }) {
  return s ? <span className={`ora-b ${s.replace(/\s+/g, '')}`}>{s}</span> : null
}

function Answer({ m, last, onSend, onGo, onItem, onUpdate, setMood }: {
  m: OraMessage
  last: boolean
  onSend: (q: string) => void
  onGo: (a: OraAction) => void
  onItem: (it: OraItem) => void
  onUpdate: (p: Partial<OraMessage>) => void
  setMood: (m: OraMood, holdMs?: number) => void
}) {
  const acts = (m.actions ?? []).filter((a) => a.type === 'navigate')
  const vote = (v: number) => {
    const nv = m.feedback === v ? 0 : v
    onUpdate({ feedback: nv || null })
    if (m.id) void oraApi.feedback(m.id, nv)
  }
  return (
    <div className={`ora-a${m.mood === 'sorry' ? ' sorry' : ''}`} data-testid="ora-answer">
      <p className="txt">{m.text}</p>
      {m.steps?.length ? <ol className="ora-steps">{m.steps.map((s, i) => <li key={i}>{s}</li>)}</ol> : null}
      {m.items?.length ? (
        <div className="ora-items">
          {m.items.map((it) => (
            <button key={it.ref} type="button" className="ora-item" onClick={() => onItem(it)}>
              <span className="r1">
                <span className="ref">{it.ref}</span>
                <Sev s={it.severity} />
                {it.band && it.band !== it.severity ? <Sev s={it.band} /> : null}
                {it.kev ? <span className="ora-b kev">KEV</span> : null}
                {it.level ? <span className="ora-b lvl">{it.level}</span> : null}
                {it.overdue ? <span className="ora-b over">Overdue</span> : null}
              </span>
              {it.title ? <span className="ti">{it.title}</span> : null}
              {it.why ? <span className="why">{it.why}</span> : null}
            </button>
          ))}
        </div>
      ) : null}
      {m.proposal ? <Card p={m.proposal} onChange={(p) => onUpdate({ proposal: p })} setMood={setMood} /> : null}
      {acts.length ? (
        <div className="ora-acts">
          {acts.map((a, i) => {
            const inApp = !!mobilePathFor(a.path, a.app_path)
            return (
              <button key={i} type="button" className="ora-go" onClick={() => onGo(a)} title={a.where}>
                <OraIcon d={ORA_ICONS.go} size={15} /> {inApp ? 'Take me there' : 'Open on web'}
              </button>
            )
          })}
        </div>
      ) : null}
      {last && m.quick_replies?.length ? (
        <div className="ora-chips">
          {m.quick_replies.map((q) => <button key={q.label} type="button" className="ora-chip qr" onClick={() => onSend(q.text)}>{q.label}</button>)}
        </div>
      ) : null}
      {last && m.suggestions?.length ? (
        <div className="ora-chips">
          {m.suggestions.map((q) => <button key={q} type="button" className="ora-chip" onClick={() => onSend(q)}>{q}</button>)}
        </div>
      ) : null}
      {m.id && m.tool !== 'proposal' ? (
        <div className="ora-fb" role="group" aria-label="Was this helpful?">
          <button type="button" className={m.feedback === 1 ? 'on' : ''} aria-label="Helpful" aria-pressed={m.feedback === 1} onClick={() => vote(1)}><OraIcon d={ORA_ICONS.up} size={17} /></button>
          <button type="button" className={m.feedback === -1 ? 'on dn' : ''} aria-label="Not helpful" aria-pressed={m.feedback === -1} onClick={() => vote(-1)}><OraIcon d={ORA_ICONS.down} size={17} /></button>
        </div>
      ) : null}
    </div>
  )
}

function Card({ p, onChange, setMood }: { p: OraProposal; onChange: (p: OraProposal) => void; setMood: (m: OraMood, holdMs?: number) => void }) {
  const [working, setWorking] = useState(false)
  const c = p.card
  const decide = async (confirm: boolean) => {
    setWorking(true)
    setMood('working')
    try {
      const r = await oraApi.decide(p.id, confirm)
      onChange(r)
      setMood(r.status === 'confirmed' ? 'happy' : 'idle', 3500)
    } catch (e) {
      onChange({ ...p, status: 'failed', result: { ok: false, message: errText(e) } })
      setMood('sorry', 3500)
    } finally {
      setWorking(false)
    }
  }
  const cls = p.status === 'confirmed' ? 'ok' : p.status === 'cancelled' || p.status === 'expired' ? 'no' : 'bad'
  return (
    <div className={`ora-card${c.danger ? ' danger' : ''}`} data-testid="ora-proposal">
      <div className="hd"><OraIcon d={c.danger ? ORA_ICONS.warn : ORA_ICONS.shield} size={16} />{c.title}</div>
      {c.lines?.length ? (
        <dl>{c.lines.map((l) => <div key={l.label} className="ln"><dt>{l.label}</dt><dd>{l.value}</dd></div>)}</dl>
      ) : null}
      {c.items?.length ? (
        <ul>{c.items.map((it) => <li key={it.ref}><span className="ref">{it.ref}</span><Sev s={it.severity} /><span className="t">{it.title}</span></li>)}</ul>
      ) : null}
      {p.status === 'pending' ? (
        <>
          {c.warning ? <div className="warn">{c.warning}</div> : null}
          <div className="ft">
            <button type="button" className="ora-btn" disabled={working} onClick={() => void decide(false)}>Cancel</button>
            <button type="button" className={`ora-btn ${c.danger ? 'd' : 'p'}`} disabled={working} onClick={() => void decide(true)}>
              {working ? 'Working…' : c.confirm || 'Confirm'}
            </button>
          </div>
        </>
      ) : (
        <div className={`res ${cls}`} role="status">{p.result?.message || (p.status === 'expired' ? 'This card expired — nothing was changed.' : p.status)}</div>
      )}
    </div>
  )
}

function History({ onOpen, onDeleted }: { onOpen: (id: number, m: OraMessage[]) => void; onDeleted: (id: number) => void }) {
  const [rows, setRows] = useState<Array<{ id: number; title: string; updated: string; surface: string }> | null>(null)
  const load = () => oraApi.conversations().then((r) => setRows(r.results)).catch(() => setRows([]))
  useEffect(() => { void load() }, [])
  if (!rows) return <div className="ora-empty">Loading…</div>
  if (!rows.length) return <div className="ora-empty">No chats yet.</div>
  return (
    <div className="ora-list">
      {rows.map((c) => (
        <div key={c.id} className="ora-row">
          <button type="button" className="open" onClick={() => oraApi.conversation(c.id).then((x) => onOpen(c.id, x.messages))}>
            <span className="t">{c.title}</span>
            <span className="d">{ago(c.updated)}{c.surface === 'web' ? ' · web' : ''}</span>
          </button>
          <button type="button" className="ora-ib" aria-label="Delete this chat" onClick={() => oraApi.deleteConversation(c.id).then(() => { onDeleted(c.id); void load() })}>
            <OraIcon d={ORA_ICONS.trash} size={18} />
          </button>
        </div>
      ))}
    </div>
  )
}

function Notes({ notice }: { notice?: string | null }) {
  const [rows, setRows] = useState<Array<{ id: number; summary: string; created: string }> | null>(null)
  const load = () => oraApi.memories().then((r) => setRows(r.results)).catch(() => setRows([]))
  useEffect(() => { void load() }, [])
  return (
    <>
      <p className="ora-muted" style={{ margin: '0 0 10px' }}>{notice || 'Short notes of earlier chats help me pick up where we left off.'}</p>
      {!rows ? <div className="ora-empty">Loading…</div> : !rows.length ? <div className="ora-empty">Nothing saved yet.</div> : (
        <div className="ora-list">
          {rows.map((n) => (
            <div key={n.id} className="ora-row">
              <span className="open"><span className="t wrap">{n.summary}</span><span className="d">{ago(n.created)}</span></span>
              <button type="button" className="ora-ib" aria-label="Forget this" onClick={() => oraApi.forget(n.id).then(load)}>
                <OraIcon d={ORA_ICONS.trash} size={18} />
              </button>
            </div>
          ))}
          <div className="ora-right"><button type="button" className="ora-btn" onClick={() => oraApi.forget().then(load)}>Forget everything</button></div>
        </div>
      )}
    </>
  )
}

