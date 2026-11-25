import { api } from '@/api/http'

/** Ora endpoints for the app (`/api/v2/orasec/mobile/ora/…`, device token). Same JSON as the web. */
export type OraMood = 'idle' | 'listening' | 'working' | 'happy' | 'sorry' | 'sleeping'

export type OraStatus = {
  available: boolean
  enabled: boolean
  configured: boolean
  hidden: boolean
  notice_ack: boolean
  notice: string
  memory_notice: string | null
  first_name: string
  superuser: boolean
}

export type OraAction = { type: 'navigate' | 'guide'; path?: string; app_path?: string | null; label?: string; where?: string; id?: string }
export type OraItem = {
  ref: string
  kind?: string
  title?: string
  severity?: string | null
  band?: string | null
  level?: string | null
  kev?: boolean
  due?: string | null
  overdue?: boolean
  asset?: string | null
  path?: string | null
  why?: string
}
export type OraCard = {
  title: string
  lines?: Array<{ label: string; value: string }>
  items?: Array<{ ref: string; title: string; severity?: string; path?: string }>
  confirm?: string
  warning?: string
  danger?: boolean
}
export type OraProposal = {
  id: string
  kind: string
  status: 'pending' | 'confirmed' | 'cancelled' | 'failed' | 'expired'
  card: OraCard
  result: { ok: boolean; message: string; path?: string | null } | null
}
export type OraMessage = {
  id?: number
  role: 'user' | 'assistant'
  text: string
  mood?: OraMood | string
  feedback?: number | null
  tool?: string
  suggestions?: string[]
  actions?: OraAction[]
  steps?: string[]
  items?: OraItem[]
  quick_replies?: Array<{ label: string; text: string }>
  proposal?: OraProposal
  created?: string
}
export type OraChatReply = { conversation_id: number; title: string; message: OraMessage }
export type OraConversationRow = { id: number; title: string; updated: string; surface: string }

const P = '/ora'

export const oraApi = {
  status: () => api<OraStatus>(`${P}/status/`),
  chat: (message: string, conversationId: number | null, page: { path: string; title: string }) =>
    api<OraChatReply>(`${P}/chat/`, { method: 'POST', body: { message, conversation_id: conversationId, page } }),
  conversations: () => api<{ results: OraConversationRow[] }>(`${P}/conversations/`),
  conversation: (id: number) => api<{ id: number; title: string; messages: OraMessage[] }>(`${P}/conversations/${id}/`),
  deleteConversation: (id: number) => api<{ ok: boolean }>(`${P}/conversations/${id}/delete/`, { method: 'POST', body: {} }),
  feedback: (id: number, value: number) => api<{ ok: boolean }>(`${P}/messages/${id}/feedback/`, { method: 'POST', body: { value } }),
  decide: (id: string, confirm: boolean) => api<OraProposal>(`${P}/proposals/${id}/`, { method: 'POST', body: { confirm } }),
  preference: (body: { hidden?: boolean; notice_ack?: boolean }) => api<OraStatus>(`${P}/preference/`, { method: 'POST', body }),
  memories: () => api<{ results: Array<{ id: number; summary: string; created: string }> }>(`${P}/memories/`),
  forget: (id?: number) => api<{ ok: boolean }>(`${P}/memories/forget/`, { method: 'POST', body: id ? { id } : {} }),
}

