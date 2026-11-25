import '@testing-library/jest-dom/vitest'

// jsdom 29 under vitest does not always expose the Web Storage globals.
// Real browsers and WKWebView always have them; give tests an in-memory shim.
if (typeof globalThis.localStorage === 'undefined') {
  const store = new Map<string, string>()
  const shim = {
    getItem: (k: string) => (store.has(k) ? store.get(k)! : null),
    setItem: (k: string, v: string) => void store.set(k, String(v)),
    removeItem: (k: string) => void store.delete(k),
    clear: () => void store.clear(),
    key: (i: number) => Array.from(store.keys())[i] ?? null,
    get length() {
      return store.size
    },
  }
  Object.defineProperty(globalThis, 'localStorage', { value: shim, configurable: true })
  if (typeof window !== 'undefined' && typeof window.localStorage === 'undefined') {
    Object.defineProperty(window, 'localStorage', { value: shim, configurable: true })
  }
}
