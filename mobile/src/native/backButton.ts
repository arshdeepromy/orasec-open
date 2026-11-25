/**
 * Android hardware/gesture back — one dispatcher for the whole app.
 *
 * iOS has no back button, so before Android every overlay (sheets, the More
 * drawer, pickers, wizard steps) only knew how to close from a tap. A raw
 * `history.back()` on Android would leave the screen underneath while the
 * overlay was still open. Instead:
 *
 *   1. Anything that is "open on top" registers a handler while it is open
 *      (see `useBackButtonClose`). Back runs the most recently registered one
 *      — the top-most overlay — and nothing else.
 *   2. With nothing open, the router fallback (`AndroidBackHandler`) decides:
 *      pop the route stack, go Home, or minimise at a root screen.
 */
type Handler = () => void

const stack: { id: number; handler: Handler }[] = []
let nextId = 1
let fallback: Handler | null = null

/** Register an overlay's close handler; returns the unregister function. */
export function pushBackHandler(handler: Handler): () => void {
  const id = nextId++
  stack.push({ id, handler })
  return () => {
    const i = stack.findIndex((e) => e.id === id)
    if (i >= 0) stack.splice(i, 1)
  }
}

/** The router-level behaviour used when no overlay is open. */
export function setBackFallback(handler: Handler): () => void {
  fallback = handler
  return () => {
    if (fallback === handler) fallback = null
  }
}

/** Run the top-most handler. Returns false when nobody handled it. */
export function handleBackButton(): boolean {
  const top = stack[stack.length - 1]
  if (top) {
    top.handler()
    return true
  }
  if (fallback) {
    fallback()
    return true
  }
  return false
}

/** Test helper. */
export function _resetBackHandlers(): void {
  stack.length = 0
  fallback = null
}
