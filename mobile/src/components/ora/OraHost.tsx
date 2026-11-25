/**
 * OraHost — Ora in the app: the floating ball (drag, snaps to an edge) and the chat sheet.
 * Long-press the ball to hide it; "Ask Ora" on the More screen (window event `ora:open`) always opens Ora
 * and shows the ball again.
 */
import { useCallback, useEffect, useRef, useState } from 'react'

import './ora-chat.css'
import OraBubble from './OraBubble'
import OraSheet from './OraSheet'
import { oraApi } from './oraApi'
import type { OraMood, OraStatus } from './oraApi'

export function openOra() {
  window.dispatchEvent(new CustomEvent('ora:open'))
}

export default function OraHost({ bubble = true }: { bubble?: boolean }) {
  const [status, setStatus] = useState<OraStatus | null>(null)
  const [open, setOpen] = useState(false)
  const [mood, setMoodState] = useState<OraMood>('idle')
  const timer = useRef<number | undefined>(undefined)

  useEffect(() => {
    let alive = true
    oraApi.status().then((s) => { if (alive) { setStatus(s); setMoodState(s.available ? 'idle' : 'sleeping') } }).catch(() => {})
    return () => { alive = false }
  }, [])

  const setMood = useCallback((m: OraMood, holdMs?: number) => {
    window.clearTimeout(timer.current)
    setMoodState(m)
    if (holdMs) timer.current = window.setTimeout(() => setMoodState(status && !status.available ? 'sleeping' : 'idle'), holdMs)
  }, [status])

  useEffect(() => {
    const onOpen = () => {
      setOpen(true)
      setStatus((s) => {
        if (s?.hidden) {
          void oraApi.preference({ hidden: false })
          return { ...s, hidden: false }
        }
        return s
      })
    }
    window.addEventListener('ora:open', onOpen)
    return () => window.removeEventListener('ora:open', onOpen)
  }, [])

  const hide = () => {
    if (!window.confirm('Hide the Ora button? You can always open Ora from More → Ask Ora.')) return
    setStatus((s) => (s ? { ...s, hidden: true } : s))
    void oraApi.preference({ hidden: true })
  }

  if (!status) return null
  return (
    <>
      {bubble && !open && !status.hidden ? <OraBubble sleeping={!status.available} onOpen={() => setOpen(true)} onLongPress={hide} /> : null}
      {open ? <OraSheet status={status} mood={mood} setMood={setMood} onClose={() => setOpen(false)} onStatus={setStatus} /> : null}
    </>
  )
}

