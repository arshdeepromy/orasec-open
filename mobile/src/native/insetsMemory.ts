/**
 * Keep the Android system-bar insets across page reloads.
 *
 * MainActivity.java publishes the real status/navigation bar sizes as CSS
 * variables (--android-inset-*) on <html>. Those live on the page, so a reload
 * (an OTA bundle switch, a crash restart) wipes them, and the native shells
 * before 1.63.9 only re-send them when the insets change. With the variables
 * gone the tab bar and sticky action bars sat on top of the 3-button
 * navigation bar.
 *
 * This remembers the last values the shell sent and puts them back at boot
 * when the shell hasn't (yet). The shell's own value always wins as soon as it
 * arrives. Storage can be unavailable; then this simply does nothing.
 */

const KEYS = ['--android-inset-top', '--android-inset-bottom', '--android-inset-left', '--android-inset-right'] as const
const STORE = 'ora.androidInsets.v1'

function readCurrent(root: HTMLElement): Record<string, string> {
  const out: Record<string, string> = {}
  for (const k of KEYS) {
    const v = root.style.getPropertyValue(k).trim()
    if (v) out[k] = v
  }
  return out
}

export function restoreAndTrackInsets(
  root: HTMLElement = document.documentElement,
  storage: Pick<Storage, 'getItem' | 'setItem'> | null = safeStorage(),
): () => void {
  if (!storage) return () => {}

  // Restore remembered values only for variables the shell hasn't set.
  try {
    const saved = JSON.parse(storage.getItem(STORE) || 'null') as Record<string, string> | null
    if (saved && typeof saved === 'object') {
      for (const k of KEYS) {
        if (!root.style.getPropertyValue(k) && typeof saved[k] === 'string' && /^\d+(\.\d+)?px$/.test(saved[k])) {
          root.style.setProperty(k, saved[k])
        }
      }
    }
  } catch {
    /* corrupt or blocked storage: ignore */
  }

  // Remember whatever the shell sends from now on.
  const save = () => {
    const cur = readCurrent(root)
    if (Object.keys(cur).length) {
      try {
        storage.setItem(STORE, JSON.stringify(cur))
      } catch {
        /* ignore */
      }
    }
  }
  save()
  if (typeof MutationObserver === 'undefined') return () => {}
  const mo = new MutationObserver(save)
  mo.observe(root, { attributes: true, attributeFilter: ['style'] })
  return () => mo.disconnect()
}

function safeStorage(): Storage | null {
  try {
    return typeof window !== 'undefined' ? window.localStorage : null
  } catch {
    return null
  }
}

