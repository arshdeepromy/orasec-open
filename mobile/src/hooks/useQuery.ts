import { type DependencyList, useCallback, useEffect, useRef, useState } from 'react'

/**
 * Minimal async data hook: loading / error / data, abort on unmount or when
 * deps change, and a `reload()` for pull-to-refresh and retry buttons.
 * Keeps the previous data while reloading so lists don't flash empty.
 */
export function useQuery<T>(
  fetcher: (signal: AbortSignal) => Promise<T>,
  deps: DependencyList,
  opts: { enabled?: boolean } = {},
) {
  const enabled = opts.enabled ?? true
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [loading, setLoading] = useState<boolean>(enabled)
  const [reloadKey, setReloadKey] = useState(0)
  const fetcherRef = useRef(fetcher)
  fetcherRef.current = fetcher

  useEffect(() => {
    if (!enabled) {
      setLoading(false)
      return
    }
    const controller = new AbortController()
    setLoading(true)
    setError(null)
    fetcherRef
      .current(controller.signal)
      .then((result) => {
        if (!controller.signal.aborted) setData(result)
      })
      .catch((err: unknown) => {
        if (controller.signal.aborted) return
        if (err instanceof DOMException && err.name === 'AbortError') return
        setError(err)
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false)
      })
    return () => controller.abort()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, reloadKey, ...deps])

  const reload = useCallback(() => setReloadKey((k) => k + 1), [])

  return { data, error, loading, reload, setData }
}
