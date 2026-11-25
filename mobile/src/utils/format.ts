/**
 * Date formatting for lists and details. en-NZ, 12-hour (matches the web,
 * which formats with hourCycle 'h12').
 */
const toDate = (value: Date | string | number | null | undefined): Date | null => {
  if (value === null || value === undefined) return null
  const d = value instanceof Date ? value : new Date(value)
  return Number.isNaN(d.getTime()) ? null : d
}

/** "Today 3:05 pm", "Yesterday", "Mon", "12 Oct", "12 Oct 2025". */
export function formatListDate(value: Date | string | number | null | undefined, now = new Date()): string {
  const d = toDate(value)
  if (!d) return ''
  const startOfDay = (x: Date) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime()
  const days = Math.round((startOfDay(now) - startOfDay(d)) / 86_400_000)
  if (days === 0) return d.toLocaleTimeString('en-NZ', { hour: 'numeric', minute: '2-digit', hour12: true })
  if (days === 1) return 'Yesterday'
  if (days > 1 && days < 7) return d.toLocaleDateString('en-NZ', { weekday: 'short' })
  if (d.getFullYear() === now.getFullYear()) return d.toLocaleDateString('en-NZ', { day: 'numeric', month: 'short' })
  return d.toLocaleDateString('en-NZ', { day: 'numeric', month: 'short', year: 'numeric' })
}

/** "12 Oct 2026, 3:05 pm" */
export function formatDateTime(value: Date | string | number | null | undefined): string {
  const d = toDate(value)
  if (!d) return ''
  return d.toLocaleString('en-NZ', {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    hour12: true,
  })
}

/** Initials for avatars: "Sam Carter" → "SC", "sam@x.nz" → "S". */
export function initials(name: string | null | undefined, email?: string | null): string {
  const source = (name ?? '').trim() || (email ?? '').trim()
  if (!source) return '?'
  const words = source.includes('@') ? [source] : source.split(/\s+/)
  const letters = words.length > 1 ? words[0][0] + words[words.length - 1][0] : words[0][0]
  return letters.toUpperCase()
}

